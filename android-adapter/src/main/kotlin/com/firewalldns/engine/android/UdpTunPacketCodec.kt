package com.firewalldns.engine.android

import java.net.InetAddress

/** A validated, complete UDP datagram extracted from one IP packet in Android TUN. */
data class UdpTunDatagram(
    val sourceAddress: InetAddress,
    val destinationAddress: InetAddress,
    val sourcePort: Int,
    val destinationPort: Int,
    val payload: ByteArray,
    val ipv4Identification: Int?,
)

/**
 * Strict codec for complete IPv4/UDP and basic IPv6/UDP packets.
 *
 * Fragmented IPv4 and IPv6 extension-header packets are deliberately rejected.
 * DNS destination port 53 is not a special case here; callers must leave it to
 * the existing DNS processor before opening a general UDP flow.
 */
object UdpTunPacketCodec {
    fun parse(packet: ByteArray): UdpTunDatagram? {
        if (packet.isEmpty()) return null
        return when ((packet[0].toInt() ushr 4) and 0x0f) {
            4 -> parseIpv4(packet)
            6 -> parseIpv6(packet)
            else -> null
        }
    }

    fun buildResponse(request: UdpTunDatagram, payload: ByteArray): ByteArray? {
        val udpLength = UDP_HEADER_BYTES + payload.size
        if (payload.isEmpty() || udpLength > 65_507) return null
        val ipv6 = request.sourceAddress.address.size == 16
        if (request.destinationAddress.address.size != request.sourceAddress.address.size) return null
        val ipHeaderLength = if (ipv6) IPV6_HEADER_BYTES else IPV4_HEADER_BYTES
        val packet = ByteArray(ipHeaderLength + udpLength)
        if (ipv6) {
            packet[0] = 0x60
            putU16(packet, 4, udpLength)
            packet[6] = IPPROTO_UDP.toByte()
            packet[7] = DEFAULT_HOP_LIMIT.toByte()
            request.destinationAddress.address.copyInto(packet, 8)
            request.sourceAddress.address.copyInto(packet, 24)
        } else {
            packet[0] = 0x45
            putU16(packet, 2, packet.size)
            putU16(packet, 4, request.ipv4Identification ?: 0)
            putU16(packet, 6, IPV4_DONT_FRAGMENT)
            packet[8] = DEFAULT_HOP_LIMIT.toByte()
            packet[9] = IPPROTO_UDP.toByte()
            request.destinationAddress.address.copyInto(packet, 12)
            request.sourceAddress.address.copyInto(packet, 16)
            putU16(packet, 10, internetChecksum(packet, 0, IPV4_HEADER_BYTES))
        }

        val udpOffset = ipHeaderLength
        putU16(packet, udpOffset, request.destinationPort)
        putU16(packet, udpOffset + 2, request.sourcePort)
        putU16(packet, udpOffset + 4, udpLength)
        payload.copyInto(packet, udpOffset + UDP_HEADER_BYTES)
        var udpChecksum = udpChecksum(
            request.destinationAddress.address,
            request.sourceAddress.address,
            packet,
            udpOffset,
            udpLength,
            ipv6,
        )
        if (udpChecksum == 0) udpChecksum = 0xffff
        putU16(packet, udpOffset + 6, udpChecksum)
        return packet
    }

    private fun parseIpv4(packet: ByteArray): UdpTunDatagram? {
        if (packet.size < IPV4_HEADER_BYTES + UDP_HEADER_BYTES) return null
        val headerLength = (packet[0].toInt() and 0x0f) * 4
        if (headerLength !in IPV4_HEADER_BYTES..60 || packet.size < headerLength + UDP_HEADER_BYTES) return null
        val totalLength = u16(packet, 2)
        if (totalLength < headerLength + UDP_HEADER_BYTES || totalLength > packet.size) return null
        if ((packet[9].toInt() and 0xff) != IPPROTO_UDP) return null
        if ((u16(packet, 6) and IPV4_FRAGMENT_MASK) != 0) return null
        if (internetChecksum(packet, 0, headerLength) != 0) return null
        val udpOffset = headerLength
        val udpLength = u16(packet, udpOffset + 4)
        if (udpLength < UDP_HEADER_BYTES || udpLength != totalLength - headerLength) return null
        val source = InetAddress.getByAddress(packet.copyOfRange(12, 16))
        val destination = InetAddress.getByAddress(packet.copyOfRange(16, 20))
        val checksum = u16(packet, udpOffset + 6)
        if (checksum != 0 && udpChecksum(
                source.address, destination.address, packet, udpOffset, udpLength, false,
            ) != 0
        ) return null
        return UdpTunDatagram(
            source, destination, u16(packet, udpOffset), u16(packet, udpOffset + 2),
            packet.copyOfRange(udpOffset + UDP_HEADER_BYTES, udpOffset + udpLength),
            u16(packet, 4),
        )
    }

    private fun parseIpv6(packet: ByteArray): UdpTunDatagram? {
        if (packet.size < IPV6_HEADER_BYTES + UDP_HEADER_BYTES) return null
        if ((packet[6].toInt() and 0xff) != IPPROTO_UDP) return null
        val payloadLength = u16(packet, 4)
        if (payloadLength < UDP_HEADER_BYTES || IPV6_HEADER_BYTES + payloadLength > packet.size) return null
        val udpOffset = IPV6_HEADER_BYTES
        val udpLength = u16(packet, udpOffset + 4)
        if (udpLength < UDP_HEADER_BYTES || udpLength != payloadLength || u16(packet, udpOffset + 6) == 0) return null
        val source = InetAddress.getByAddress(packet.copyOfRange(8, 24))
        val destination = InetAddress.getByAddress(packet.copyOfRange(24, 40))
        if (udpChecksum(source.address, destination.address, packet, udpOffset, udpLength, true) != 0) return null
        return UdpTunDatagram(
            source, destination, u16(packet, udpOffset), u16(packet, udpOffset + 2),
            packet.copyOfRange(udpOffset + UDP_HEADER_BYTES, udpOffset + udpLength), null,
        )
    }

    private fun udpChecksum(
        source: ByteArray,
        destination: ByteArray,
        packet: ByteArray,
        offset: Int,
        length: Int,
        ipv6: Boolean,
    ): Int {
        var sum = 0L
        fun add(bytes: ByteArray) {
            var index = 0
            while (index + 1 < bytes.size) {
                sum += (((bytes[index].toInt() and 0xff) shl 8) or (bytes[index + 1].toInt() and 0xff)).toLong()
                index += 2
            }
            if (index < bytes.size) sum += ((bytes[index].toInt() and 0xff) shl 8).toLong()
        }
        add(source)
        add(destination)
        if (ipv6) {
            sum += (length ushr 16).toLong()
            sum += (length and 0xffff).toLong()
            sum += IPPROTO_UDP.toLong()
        } else {
            sum += IPPROTO_UDP.toLong()
            sum += length.toLong()
        }
        var index = offset
        val end = offset + length
        while (index + 1 < end) {
            sum += (((packet[index].toInt() and 0xff) shl 8) or (packet[index + 1].toInt() and 0xff)).toLong()
            index += 2
        }
        if (index < end) sum += ((packet[index].toInt() and 0xff) shl 8).toLong()
        return foldChecksum(sum)
    }

    private fun internetChecksum(packet: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var index = offset
        val end = offset + length
        while (index + 1 < end) {
            sum += (((packet[index].toInt() and 0xff) shl 8) or (packet[index + 1].toInt() and 0xff)).toLong()
            index += 2
        }
        if (index < end) sum += ((packet[index].toInt() and 0xff) shl 8).toLong()
        return foldChecksum(sum)
    }

    private fun foldChecksum(value: Long): Int {
        var sum = value
        while ((sum ushr 16) != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.toInt().inv() and 0xffff
    }

    private fun u16(packet: ByteArray, offset: Int): Int =
        ((packet[offset].toInt() and 0xff) shl 8) or (packet[offset + 1].toInt() and 0xff)

    private fun putU16(packet: ByteArray, offset: Int, value: Int) {
        packet[offset] = (value ushr 8).toByte()
        packet[offset + 1] = value.toByte()
    }

    private const val IPV4_HEADER_BYTES = 20
    private const val IPV6_HEADER_BYTES = 40
    private const val UDP_HEADER_BYTES = 8
    private const val IPPROTO_UDP = 17
    private const val IPV4_FRAGMENT_MASK = 0x3fff
    private const val IPV4_DONT_FRAGMENT = 0x4000
    private const val DEFAULT_HOP_LIMIT = 64
}
