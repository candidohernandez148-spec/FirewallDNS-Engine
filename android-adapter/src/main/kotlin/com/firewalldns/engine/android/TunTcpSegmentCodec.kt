package com.firewalldns.engine.android

/**
 * Pure IPv4/IPv6 + TCP segment codec with IPv4 header checksum, IPv6 extension header walking,
 * MSS option parsing, and RFC 9293 TCP pseudo-header checksum verification/generation.
 */
internal object TunTcpSegmentCodec {
    const val FLAG_FIN = 0x01
    const val FLAG_SYN = 0x02
    const val FLAG_RST = 0x04
    const val FLAG_PSH = 0x08
    const val FLAG_ACK = 0x10

    data class DecodedTcpPacket(
        val ipv6: Boolean,
        val ipHeaderLength: Int,
        val sourceAddress: ByteArray,
        val destinationAddress: ByteArray,
        val sourcePort: Int,
        val destinationPort: Int,
        val sequenceNumber: Long,
        val ackNumber: Long,
        val flags: Int,
        val windowSize: Int,
        val mss: Int?,
        val payload: ByteArray,
    ) {
        val isFin: Boolean get() = (flags and FLAG_FIN) != 0
        val isSyn: Boolean get() = (flags and FLAG_SYN) != 0
        val isRst: Boolean get() = (flags and FLAG_RST) != 0
        val isPsh: Boolean get() = (flags and FLAG_PSH) != 0
        val isAck: Boolean get() = (flags and FLAG_ACK) != 0
    }

    sealed interface DecodeResult {
        data class Valid(val packet: DecodedTcpPacket) : DecodeResult
        data class Invalid(val reason: String) : DecodeResult
    }

    fun decode(packet: ByteArray, length: Int = packet.size): DecodeResult {
        if (length <= 0 || length > packet.size) return DecodeResult.Invalid("invalid_packet_length")
        return when ((packet[0].toInt() ushr 4) and 0x0f) {
            4 -> decodeIpv4(packet, length)
            6 -> decodeIpv6(packet, length)
            else -> DecodeResult.Invalid("unsupported_ip_version")
        }
    }

    private fun decodeIpv4(packet: ByteArray, length: Int): DecodeResult {
        if (length < 20) return DecodeResult.Invalid("ipv4_header_truncated")
        val headerLength = (packet[0].toInt() and 0x0f) * 4
        if (headerLength < 20 || headerLength > length) return DecodeResult.Invalid("ipv4_header_length_invalid")
        val totalLength = u16(packet, 2)
        if (totalLength < headerLength || totalLength > length) return DecodeResult.Invalid("ipv4_total_length_invalid")
        if (internetChecksum(packet, 0, headerLength) != 0) {
            return DecodeResult.Invalid("ipv4_header_checksum_invalid")
        }
        val protocol = packet[9].toInt() and 0xff
        if (protocol != IPPROTO_TCP) return DecodeResult.Invalid("not_tcp_protocol")
        if ((u16(packet, 6) and 0x3fff) != 0) return DecodeResult.Invalid("ipv4_fragment_unsupported")
        return decodeTcp(
            packet = packet,
            ipv6 = false,
            ipHeaderLength = headerLength,
            tcpOffset = headerLength,
            packetEnd = totalLength,
            sourceAddress = packet.copyOfRange(12, 16),
            destinationAddress = packet.copyOfRange(16, 20),
        )
    }

    private fun decodeIpv6(packet: ByteArray, length: Int): DecodeResult {
        if (length < 40) return DecodeResult.Invalid("ipv6_header_truncated")
        val payloadLength = u16(packet, 4)
        val packetEnd = 40 + payloadLength
        if (payloadLength == 0 || packetEnd > length) return DecodeResult.Invalid("ipv6_payload_length_invalid")

        var nextHeader = packet[6].toInt() and 0xff
        var offset = 40
        var extensions = 0
        while (nextHeader in IPV6_EXTENSION_HEADERS) {
            if (++extensions > 8) return DecodeResult.Invalid("ipv6_extension_chain_too_long")
            if (nextHeader == 44) {
                if (offset + 8 > packetEnd) return DecodeResult.Invalid("ipv6_fragment_header_truncated")
                val fragmentField = u16(packet, offset + 2)
                if ((fragmentField and 0xfff9) != 0) {
                    return DecodeResult.Invalid("ipv6_fragment_unsupported")
                }
                nextHeader = packet[offset].toInt() and 0xff
                offset += 8
                continue
            }
            if (offset + 2 > packetEnd) return DecodeResult.Invalid("ipv6_extension_header_truncated")
            val following = packet[offset].toInt() and 0xff
            val extLen = if (nextHeader == 51) {
                ((packet[offset + 1].toInt() and 0xff) + 2) * 4
            } else {
                ((packet[offset + 1].toInt() and 0xff) + 1) * 8
            }
            if (extLen < 8 || offset + extLen > packetEnd) {
                return DecodeResult.Invalid("ipv6_extension_length_invalid")
            }
            nextHeader = following
            offset += extLen
        }

        if (nextHeader != IPPROTO_TCP) return DecodeResult.Invalid("not_tcp_protocol")
        return decodeTcp(
            packet = packet,
            ipv6 = true,
            ipHeaderLength = 40,
            tcpOffset = offset,
            packetEnd = packetEnd,
            sourceAddress = packet.copyOfRange(8, 24),
            destinationAddress = packet.copyOfRange(24, 40),
        )
    }

    private fun decodeTcp(
        packet: ByteArray,
        ipv6: Boolean,
        ipHeaderLength: Int,
        tcpOffset: Int,
        packetEnd: Int,
        sourceAddress: ByteArray,
        destinationAddress: ByteArray,
    ): DecodeResult {
        val tcpLength = packetEnd - tcpOffset
        if (tcpLength < 20) return DecodeResult.Invalid("tcp_header_truncated")
        val dataOffset = ((packet[tcpOffset + 12].toInt() ushr 4) and 0x0f) * 4
        if (dataOffset < 20 || dataOffset > tcpLength) {
            return DecodeResult.Invalid("tcp_data_offset_invalid")
        }
        if (tcpChecksum(ipv6, sourceAddress, destinationAddress, packet, tcpOffset, tcpLength) != 0) {
            return DecodeResult.Invalid("tcp_checksum_invalid")
        }

        val sourcePort = u16(packet, tcpOffset)
        val destinationPort = u16(packet, tcpOffset + 2)
        val seq = u32(packet, tcpOffset + 4)
        val ack = u32(packet, tcpOffset + 8)
        val flags = packet[tcpOffset + 13].toInt() and 0x3f
        val windowSize = u16(packet, tcpOffset + 14)
        val mss = parseMssOption(packet, tcpOffset + 20, tcpOffset + dataOffset)
        val payload = packet.copyOfRange(tcpOffset + dataOffset, packetEnd)

        return DecodeResult.Valid(
            DecodedTcpPacket(
                ipv6 = ipv6,
                ipHeaderLength = ipHeaderLength,
                sourceAddress = sourceAddress,
                destinationAddress = destinationAddress,
                sourcePort = sourcePort,
                destinationPort = destinationPort,
                sequenceNumber = seq,
                ackNumber = ack,
                flags = flags,
                windowSize = windowSize,
                mss = mss,
                payload = payload,
            ),
        )
    }

    fun encode(
        ipv6: Boolean,
        sourceAddress: ByteArray,
        destinationAddress: ByteArray,
        sourcePort: Int,
        destinationPort: Int,
        sequenceNumber: Long,
        ackNumber: Long,
        flags: Int,
        windowSize: Int,
        mssOption: Int? = null,
        payload: ByteArray = ByteArray(0),
    ): ByteArray {
        val ipHeaderLen = if (ipv6) 40 else 20
        val optionsLen = if (mssOption != null) 4 else 0
        val tcpHeaderLen = 20 + optionsLen
        val tcpLen = tcpHeaderLen + payload.size
        val totalLen = ipHeaderLen + tcpLen
        val out = ByteArray(totalLen)

        if (ipv6) {
            out[0] = 0x60
            putU16(out, 4, tcpLen)
            out[6] = IPPROTO_TCP.toByte()
            out[7] = 64
            sourceAddress.copyInto(out, 8)
            destinationAddress.copyInto(out, 24)
        } else {
            out[0] = 0x45
            putU16(out, 2, totalLen)
            putU16(out, 6, 0x4000) // DF
            out[8] = 64
            out[9] = IPPROTO_TCP.toByte()
            sourceAddress.copyInto(out, 12)
            destinationAddress.copyInto(out, 16)
            putU16(out, 10, internetChecksum(out, 0, 20))
        }

        val tcpOffset = ipHeaderLen
        putU16(out, tcpOffset, sourcePort)
        putU16(out, tcpOffset + 2, destinationPort)
        putU32(out, tcpOffset + 4, sequenceNumber)
        putU32(out, tcpOffset + 8, ackNumber)
        out[tcpOffset + 12] = ((tcpHeaderLen / 4) shl 4).toByte()
        out[tcpOffset + 13] = (flags and 0x3f).toByte()
        putU16(out, tcpOffset + 14, windowSize.coerceIn(0, 65_535))
        if (mssOption != null) {
            out[tcpOffset + 20] = 2
            out[tcpOffset + 21] = 4
            putU16(out, tcpOffset + 22, mssOption.coerceIn(536, 65_535))
        }
        if (payload.isNotEmpty()) {
            payload.copyInto(out, tcpOffset + tcpHeaderLen)
        }
        val checksum = tcpChecksum(ipv6, sourceAddress, destinationAddress, out, tcpOffset, tcpLen)
        putU16(out, tcpOffset + 16, checksum)
        return out
    }

    private fun parseMssOption(packet: ByteArray, start: Int, end: Int): Int? {
        var i = start
        while (i < end) {
            val kind = packet[i].toInt() and 0xff
            if (kind == 0) break
            if (kind == 1) {
                i++
                continue
            }
            if (i + 1 >= end) break
            val len = packet[i + 1].toInt() and 0xff
            if (len < 2 || i + len > end) break
            if (kind == 2 && len == 4) {
                return u16(packet, i + 2)
            }
            i += len
        }
        return null
    }

    private fun tcpChecksum(
        ipv6: Boolean,
        source: ByteArray,
        destination: ByteArray,
        packet: ByteArray,
        offset: Int,
        length: Int,
    ): Int {
        var sum = 0L
        fun add(data: ByteArray, start: Int, count: Int) {
            var i = start
            val end = start + count
            while (i + 1 < end) {
                sum += (((data[i].toInt() and 0xff) shl 8) or (data[i + 1].toInt() and 0xff)).toLong()
                i += 2
            }
            if (i < end) sum += ((data[i].toInt() and 0xff) shl 8).toLong()
        }
        add(source, 0, source.size)
        add(destination, 0, destination.size)
        if (ipv6) {
            sum += ((length ushr 16) and 0xffff).toLong()
            sum += (length and 0xffff).toLong()
            sum += IPPROTO_TCP.toLong()
        } else {
            sum += IPPROTO_TCP.toLong()
            sum += length.toLong()
        }
        add(packet, offset, length)
        while ((sum ushr 16) != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.toInt().inv() and 0xffff
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

    private fun putU32(data: ByteArray, offset: Int, value: Long) {
        data[offset] = (value ushr 24).toByte()
        data[offset + 1] = (value ushr 16).toByte()
        data[offset + 2] = (value ushr 8).toByte()
        data[offset + 3] = value.toByte()
    }

    private const val IPPROTO_TCP = 6
    private val IPV6_EXTENSION_HEADERS = setOf(0, 43, 44, 51, 60)
}
