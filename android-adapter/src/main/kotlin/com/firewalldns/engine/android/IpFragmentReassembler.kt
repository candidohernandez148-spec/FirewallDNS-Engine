package com.firewalldns.engine.android

import java.util.LinkedHashMap

data class FragmentReassemblerConfig(
    val maxPendingAssemblies: Int = 32,
    val maxTotalBufferedBytes: Int = 256 * 1024,
    val maxReassembledPacketBytes: Int = 16 * 1024,
    val fragmentTimeoutMillis: Long = 5_000L,
) {
    init {
        require(maxPendingAssemblies in 1..1024)
        require(maxTotalBufferedBytes >= 4096)
        require(maxReassembledPacketBytes in 1500..65_535)
        require(fragmentTimeoutMillis > 0L)
    }
}

data class FragmentReassemblerMetrics(
    val pendingAssemblies: Int,
    val bufferedBytes: Int,
    val fragmentsAccepted: Long,
    val packetsReassembled: Long,
    val fragmentsDroppedInvalid: Long,
    val fragmentsDroppedLimit: Long,
    val assembliesExpired: Long,
)

/**
 * Bounded, monotonic-TTL IPv4 and IPv6 fragment reassembler for TUN ingress packets.
 *
 * Non-fragmented packets pass straight through without buffering. Fragmented packets are
 * buffered per (ipVersion, src, dst, protocol/identification) until all contiguous ranges
 * from offset 0 through the final fragment arrive, then reassembled into a valid single
 * non-fragmented IP packet.
 */
class IpFragmentReassembler(
    private val config: FragmentReassemblerConfig = FragmentReassemblerConfig(),
    private val clockNanos: () -> Long = System::nanoTime,
) {
    sealed interface Result {
        data class Ready(val packet: ByteArray, val length: Int, val wasFragmented: Boolean) : Result
        data object Pending : Result
        data class Dropped(val reason: String) : Result
    }

    private data class FragmentKey(
        val ipv6: Boolean,
        val sourceAddress: ByteArray,
        val destinationAddress: ByteArray,
        val protocolOrZero: Int,
        val identification: Long,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is FragmentKey) return false
            return ipv6 == other.ipv6 &&
                protocolOrZero == other.protocolOrZero &&
                identification == other.identification &&
                sourceAddress.contentEquals(other.sourceAddress) &&
                destinationAddress.contentEquals(other.destinationAddress)
        }

        override fun hashCode(): Int {
            var h = ipv6.hashCode()
            h = 31 * h + sourceAddress.contentHashCode()
            h = 31 * h + destinationAddress.contentHashCode()
            h = 31 * h + protocolOrZero
            h = 31 * h + identification.hashCode()
            return h
        }
    }

    private data class FragmentSlice(
        val offset: Int,
        val data: ByteArray,
    )

    private class Assembly(
        val key: FragmentKey,
        val baseHeader: ByteArray,
        val upperLayerProtocol: Int,
        val createdAtNanos: Long,
    ) {
        val slices = ArrayList<FragmentSlice>()
        var totalPayloadLength: Int? = null
        var bufferedBytes: Int = 0
    }

    private val lock = Any()
    private val assemblies = LinkedHashMap<FragmentKey, Assembly>(16, 0.75f, true)
    private var totalBufferedBytes = 0

    private var fragmentsAccepted = 0L
    private var packetsReassembled = 0L
    private var fragmentsDroppedInvalid = 0L
    private var fragmentsDroppedLimit = 0L
    private var assembliesExpired = 0L

    fun process(packet: ByteArray, length: Int = packet.size): Result {
        if (length <= 0 || length > packet.size) {
            synchronized(lock) { fragmentsDroppedInvalid++ }
            return Result.Dropped("invalid_packet_length")
        }
        return when ((packet[0].toInt() ushr 4) and 0x0f) {
            4 -> processIpv4(packet, length)
            6 -> processIpv6(packet, length)
            else -> Result.Ready(packet, length, wasFragmented = false)
        }
    }

    fun evictExpired(): Int {
        synchronized(lock) {
            return evictExpiredLocked(clockNanos())
        }
    }

    fun clear() {
        synchronized(lock) {
            assemblies.clear()
            totalBufferedBytes = 0
        }
    }

    fun metrics(): FragmentReassemblerMetrics = synchronized(lock) {
        FragmentReassemblerMetrics(
            pendingAssemblies = assemblies.size,
            bufferedBytes = totalBufferedBytes,
            fragmentsAccepted = fragmentsAccepted,
            packetsReassembled = packetsReassembled,
            fragmentsDroppedInvalid = fragmentsDroppedInvalid,
            fragmentsDroppedLimit = fragmentsDroppedLimit,
            assembliesExpired = assembliesExpired,
        )
    }

    private fun processIpv4(packet: ByteArray, length: Int): Result {
        if (length < 20) return Result.Ready(packet, length, wasFragmented = false)
        val ihl = (packet[0].toInt() and 0x0f) * 4
        val totalLen = u16(packet, 2)
        if (ihl < 20 || ihl > length || totalLen < ihl || totalLen > length) {
            return Result.Ready(packet, length, wasFragmented = false)
        }
        val flagsAndOffset = u16(packet, 6)
        val moreFragments = (flagsAndOffset and 0x2000) != 0
        val fragOffsetBytes = (flagsAndOffset and 0x1fff) * 8
        if (!moreFragments && fragOffsetBytes == 0) {
            return Result.Ready(packet, length, wasFragmented = false)
        }
        if (internetChecksum(packet, 0, ihl) != 0) {
            synchronized(lock) { fragmentsDroppedInvalid++ }
            return Result.Dropped("ipv4_fragment_header_checksum_invalid")
        }
        val payloadLen = totalLen - ihl
        if (payloadLen <= 0 || (moreFragments && payloadLen % 8 != 0)) {
            synchronized(lock) { fragmentsDroppedInvalid++ }
            return Result.Dropped("ipv4_fragment_alignment_or_length_invalid")
        }
        val ident = u16(packet, 4).toLong()
        val protocol = packet[9].toInt() and 0xff
        val key = FragmentKey(
            ipv6 = false,
            sourceAddress = packet.copyOfRange(12, 16),
            destinationAddress = packet.copyOfRange(16, 20),
            protocolOrZero = protocol,
            identification = ident,
        )
        val payload = packet.copyOfRange(ihl, totalLen)
        val baseHeader = if (fragOffsetBytes == 0) packet.copyOfRange(0, ihl) else null
        return addFragment(key, fragOffsetBytes, moreFragments, payload, baseHeader, protocol)
    }

    private fun processIpv6(packet: ByteArray, length: Int): Result {
        if (length < 40) return Result.Ready(packet, length, wasFragmented = false)
        val payloadLength = u16(packet, 4)
        val packetEnd = 40 + payloadLength
        if (payloadLength == 0 || packetEnd > length) {
            return Result.Ready(packet, length, wasFragmented = false)
        }

        var nextHeader = packet[6].toInt() and 0xff
        var offset = 40
        var extensions = 0
        var unfragmentableEnd = 40
        var prevNextHeaderOffset = 6

        while (nextHeader in IPV6_EXTENSION_HEADERS) {
            if (++extensions > 8) {
                return Result.Ready(packet, length, wasFragmented = false)
            }
            if (nextHeader == IPV6_FRAGMENT_HEADER) {
                if (offset + 8 > packetEnd) {
                    synchronized(lock) { fragmentsDroppedInvalid++ }
                    return Result.Dropped("ipv6_fragment_header_truncated")
                }
                val upperProto = packet[offset].toInt() and 0xff
                val fragField = u16(packet, offset + 2)
                val moreFragments = (fragField and 0x0001) != 0
                val fragOffsetBytes = (fragField and 0xfff8)
                if (!moreFragments && fragOffsetBytes == 0) {
                    return Result.Ready(packet, length, wasFragmented = false)
                }
                val payloadLen = packetEnd - (offset + 8)
                if (payloadLen <= 0 || (moreFragments && payloadLen % 8 != 0)) {
                    synchronized(lock) { fragmentsDroppedInvalid++ }
                    return Result.Dropped("ipv6_fragment_alignment_or_length_invalid")
                }
                val ident = u32(packet, offset + 4)
                val key = FragmentKey(
                    ipv6 = true,
                    sourceAddress = packet.copyOfRange(8, 24),
                    destinationAddress = packet.copyOfRange(24, 40),
                    protocolOrZero = 0,
                    identification = ident,
                )
                val payload = packet.copyOfRange(offset + 8, packetEnd)
                val baseHeader = if (fragOffsetBytes == 0) {
                    packet.copyOfRange(0, unfragmentableEnd).also { hdr ->
                        hdr[prevNextHeaderOffset] = upperProto.toByte()
                    }
                } else {
                    null
                }
                return addFragment(key, fragOffsetBytes, moreFragments, payload, baseHeader, upperProto)
            }
            if (offset + 2 > packetEnd) {
                return Result.Ready(packet, length, wasFragmented = false)
            }
            val following = packet[offset].toInt() and 0xff
            val extLen = if (nextHeader == 51) {
                ((packet[offset + 1].toInt() and 0xff) + 2) * 4
            } else {
                ((packet[offset + 1].toInt() and 0xff) + 1) * 8
            }
            if (extLen < 8 || offset + extLen > packetEnd) {
                return Result.Ready(packet, length, wasFragmented = false)
            }
            prevNextHeaderOffset = offset
            nextHeader = following
            offset += extLen
            unfragmentableEnd = offset
        }

        return Result.Ready(packet, length, wasFragmented = false)
    }

    private fun addFragment(
        key: FragmentKey,
        fragOffset: Int,
        moreFragments: Boolean,
        payload: ByteArray,
        baseHeader: ByteArray?,
        upperProtocol: Int,
    ): Result {
        val endOffset = fragOffset + payload.size
        if (endOffset > config.maxReassembledPacketBytes) {
            synchronized(lock) { fragmentsDroppedLimit++ }
            return Result.Dropped("fragment_reassembly_packet_too_large")
        }

        val now = clockNanos()
        synchronized(lock) {
            evictExpiredLocked(now)

            var assembly = assemblies[key]
            if (assembly == null) {
                if (assemblies.size >= config.maxPendingAssemblies) {
                    val oldestKey = assemblies.keys.firstOrNull()
                    if (oldestKey != null) {
                        val evicted = assemblies.remove(oldestKey)
                        if (evicted != null) {
                            totalBufferedBytes -= evicted.bufferedBytes
                        }
                    }
                    fragmentsDroppedLimit++
                }
                if (totalBufferedBytes + payload.size > config.maxTotalBufferedBytes) {
                    fragmentsDroppedLimit++
                    return Result.Dropped("fragment_buffer_budget_exhausted")
                }
                assembly = Assembly(
                    key = key,
                    baseHeader = baseHeader ?: ByteArray(0),
                    upperLayerProtocol = upperProtocol,
                    createdAtNanos = now,
                )
                assemblies[key] = assembly
            } else {
                if (totalBufferedBytes + payload.size > config.maxTotalBufferedBytes) {
                    fragmentsDroppedLimit++
                    return Result.Dropped("fragment_buffer_budget_exhausted")
                }
                if (fragOffset == 0 && baseHeader != null && assembly.baseHeader.isEmpty()) {
                    assembly = Assembly(
                        key = key,
                        baseHeader = baseHeader,
                        upperLayerProtocol = upperProtocol,
                        createdAtNanos = assembly.createdAtNanos,
                    ).also { updated ->
                        updated.slices.addAll(assembly.slices)
                        updated.totalPayloadLength = assembly.totalPayloadLength
                        updated.bufferedBytes = assembly.bufferedBytes
                        assemblies[key] = updated
                    }
                }
            }

            // Reject overlapping fragments (RFC 5722 / RFC 6864 hardening)
            for (existing in assembly.slices) {
                val existingEnd = existing.offset + existing.data.size
                if (fragOffset < existingEnd && endOffset > existing.offset) {
                    if (fragOffset == existing.offset && endOffset == existingEnd) {
                        // Identical duplicate fragment: ignore idempotently
                        return Result.Pending
                    }
                    assemblies.remove(key)
                    totalBufferedBytes -= assembly.bufferedBytes
                    fragmentsDroppedInvalid++
                    return Result.Dropped("fragment_overlap_rejected")
                }
            }

            if (!moreFragments) {
                val previousTotal = assembly.totalPayloadLength
                if (previousTotal != null && previousTotal != endOffset) {
                    assemblies.remove(key)
                    totalBufferedBytes -= assembly.bufferedBytes
                    fragmentsDroppedInvalid++
                    return Result.Dropped("fragment_inconsistent_final_length")
                }
                assembly.totalPayloadLength = endOffset
            }

            assembly.slices.add(FragmentSlice(fragOffset, payload))
            assembly.bufferedBytes += payload.size
            totalBufferedBytes += payload.size
            fragmentsAccepted++

            val expectedTotal = assembly.totalPayloadLength
            if (expectedTotal != null && assembly.baseHeader.isNotEmpty() && isComplete(assembly, expectedTotal)) {
                assemblies.remove(key)
                totalBufferedBytes -= assembly.bufferedBytes
                val assembled = buildReassembledPacket(assembly, expectedTotal)
                    ?: run {
                        fragmentsDroppedInvalid++
                        return Result.Dropped("fragment_reassembled_exceeds_mtu_limit")
                    }
                packetsReassembled++
                return Result.Ready(assembled, assembled.size, wasFragmented = true)
            }
            return Result.Pending
        }
    }

    private fun isComplete(assembly: Assembly, expectedTotal: Int): Boolean {
        val sorted = assembly.slices.sortedBy { it.offset }
        var cursor = 0
        for (slice in sorted) {
            if (slice.offset != cursor) return false
            cursor += slice.data.size
        }
        return cursor == expectedTotal
    }

    private fun buildReassembledPacket(assembly: Assembly, payloadTotal: Int): ByteArray? {
        val header = assembly.baseHeader
        val totalPacketLen = header.size + payloadTotal
        if (totalPacketLen > 65_535 || totalPacketLen > config.maxReassembledPacketBytes) return null
        val out = ByteArray(totalPacketLen)
        header.copyInto(out, 0)
        for (slice in assembly.slices) {
            slice.data.copyInto(out, header.size + slice.offset)
        }
        if (assembly.key.ipv6) {
            val ipv6PayloadLen = (header.size - 40) + payloadTotal
            if (ipv6PayloadLen > 65_535) return null
            putU16(out, 4, ipv6PayloadLen)
        } else {
            putU16(out, 2, totalPacketLen)
            putU16(out, 6, 0) // clear MF & fragment offset
            putU16(out, 10, 0)
            putU16(out, 10, internetChecksum(out, 0, header.size))
        }
        return out
    }

    private fun evictExpiredLocked(nowNanos: Long): Int {
        val ttlNanos = config.fragmentTimeoutMillis * 1_000_000L
        var expired = 0
        val iter = assemblies.entries.iterator()
        while (iter.hasNext()) {
            val entry = iter.next()
            if (nowNanos - entry.value.createdAtNanos >= ttlNanos) {
                totalBufferedBytes -= entry.value.bufferedBytes
                iter.remove()
                assembliesExpired++
                expired++
            }
        }
        return expired
    }

    private fun internetChecksum(data: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = offset
        val end = offset + length
        while (i + 1 < end) {
            sum += (((data[i].toInt() and 0xff) shl 8) or (data[i + 1].toInt() and 0xff)).toLong()
            i += 2
        }
        if (i < end) sum += ((data[i].toInt() and 0xff) shl 8).toLong()
        while ((sum ushr 16) != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.toInt().inv() and 0xffff
    }

    private fun u16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xff) shl 8) or (data[offset + 1].toInt() and 0xff)

    private fun u32(data: ByteArray, offset: Int): Long =
        ((data[offset].toLong() and 0xff) shl 24) or
            ((data[offset + 1].toLong() and 0xff) shl 16) or
            ((data[offset + 2].toLong() and 0xff) shl 8) or
            (data[offset + 3].toLong() and 0xff)

    private fun putU16(data: ByteArray, offset: Int, value: Int) {
        data[offset] = (value ushr 8).toByte()
        data[offset + 1] = value.toByte()
    }

    private companion object {
        const val IPV6_FRAGMENT_HEADER = 44
        val IPV6_EXTENSION_HEADERS = setOf(0, 43, 44, 51, 60)
    }
}
