package com.firewalldns.diagnostics

/**
 * Minimal IPv4/UDP decoder for the diagnostic TUN route.
 * Inspection exposes header metadata only; packet payload is never copied or retained.
 */
internal object Ipv4UdpProbeParser {
    const val MAGIC: Int = 0x46444e53 // "FDNS"
    const val DESTINATION_IPV4: Int = -971898879 // 198.18.0.1
    const val DESTINATION_PORT: Int = 4242

    data class Probe(val sequence: Int)

    data class Inspection(
        val probe: Probe?,
        val rejection: String?,
        val packetLength: Int,
        val ipVersion: Int?,
        val protocol: Int?,
        val destinationIpv4: String?,
        val destinationPort: Int?,
        val udpLength: Int?,
    )

    fun parse(packet: ByteArray, length: Int): Probe? = inspect(packet, length).probe

    fun inspect(packet: ByteArray, length: Int): Inspection {
        if (length < 0 || length > packet.size || length < 1) {
            return rejected("invalid_packet_length", length.coerceAtLeast(0))
        }
        val versionAndIhl = packet[0].toInt() and 0xff
        val version = versionAndIhl ushr 4
        if (version != 4) {
            return rejected("not_ipv4", length, version = version)
        }
        if (length < 20) {
            return rejected("truncated_ipv4_header", length, version = version)
        }
        val headerLength = (versionAndIhl and 0x0f) * 4
        if (headerLength < 20 || headerLength > length) {
            return rejected("invalid_ipv4_header_length", length, version = version)
        }
        val totalLength = u16(packet, 2)
        if (totalLength < headerLength || totalLength > length) {
            return rejected("invalid_ipv4_total_length", length, version, packet[9].toInt() and 0xff)
        }
        val protocol = packet[9].toInt() and 0xff
        val destination = ipv4(u32(packet, 16))
        if (protocol != 17) {
            return rejected("not_udp", length, version, protocol, destination)
        }
        val fragment = u16(packet, 6)
        if ((fragment and 0x3fff) != 0) {
            return rejected("fragmented_ipv4", length, version, protocol, destination)
        }
        if (totalLength < headerLength + 8) {
            return rejected("truncated_udp_header", length, version, protocol, destination)
        }
        val udpOffset = headerLength
        val udpLength = u16(packet, udpOffset + 4)
        val destinationPort = u16(packet, udpOffset + 2)
        if (destinationValue(packet) != DESTINATION_IPV4) {
            return rejected("wrong_destination", length, version, protocol, destination, destinationPort, udpLength)
        }
        if (udpLength < 8 || udpOffset + udpLength > totalLength) {
            return rejected("invalid_udp_length", length, version, protocol, destination, destinationPort, udpLength)
        }
        if (destinationPort != DESTINATION_PORT) {
            return rejected("wrong_udp_port", length, version, protocol, destination, destinationPort, udpLength)
        }
        if (udpLength < 16 || totalLength < udpOffset + 16) {
            return rejected("probe_payload_truncated", length, version, protocol, destination, destinationPort, udpLength)
        }
        val payloadOffset = udpOffset + 8
        if (u32(packet, payloadOffset) != MAGIC) {
            return rejected("wrong_probe_magic", length, version, protocol, destination, destinationPort, udpLength)
        }
        return Inspection(
            Probe(u32(packet, payloadOffset + 4)),
            null,
            length,
            version,
            protocol,
            destination,
            destinationPort,
            udpLength,
        )
    }

    private fun rejected(
        reason: String,
        length: Int,
        version: Int? = null,
        protocol: Int? = null,
        destination: String? = null,
        destinationPort: Int? = null,
        udpLength: Int? = null,
    ) = Inspection(null, reason, length, version, protocol, destination, destinationPort, udpLength)

    private fun destinationValue(data: ByteArray): Int = u32(data, 16)

    private fun ipv4(value: Int): String =
        "${(value ushr 24) and 0xff}.${(value ushr 16) and 0xff}.${(value ushr 8) and 0xff}.${value and 0xff}"

    private fun u16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xff) shl 8) or (data[offset + 1].toInt() and 0xff)

    private fun u32(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xff) shl 24) or
            ((data[offset + 1].toInt() and 0xff) shl 16) or
            ((data[offset + 2].toInt() and 0xff) shl 8) or
            (data[offset + 3].toInt() and 0xff)
}
