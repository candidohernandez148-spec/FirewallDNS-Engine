package com.firewalldns.diagnostics

/**
 * Minimal, allocation-light IPv4/UDP decoder for the diagnostic TUN route.
 * It never parses or stores arbitrary packet contents.
 */
internal object Ipv4UdpProbeParser {
    const val MAGIC: Int = 0x46444e53 // "FDNS"
    const val DESTINATION_IPV4: Int = 0xC6120001.toInt() // 198.18.0.1
    const val DESTINATION_PORT: Int = 4242

    data class Probe(val sequence: Int)

    fun parse(packet: ByteArray, length: Int): Probe? {
        if (length < 20 || length > packet.size) return null
        val versionAndIhl = packet[0].toInt() and 0xff
        if ((versionAndIhl ushr 4) != 4) return null
        val headerLength = (versionAndIhl and 0x0f) * 4
        if (headerLength < 20 || headerLength > length) return null
        val totalLength = u16(packet, 2)
        if (totalLength < headerLength + 8 || totalLength > length) return null
        if ((packet[9].toInt() and 0xff) != 17) return null
        // Ignore fragmented packets; the test datagrams must fit in one IPv4 packet.
        val fragment = u16(packet, 6)
        if ((fragment and 0x3fff) != 0) return null
        val destination = u32(packet, 16)
        if (destination != DESTINATION_IPV4) return null
        val udpOffset = headerLength
        val udpLength = u16(packet, udpOffset + 4)
        if (udpLength < 16 || udpOffset + udpLength > totalLength) return null
        if (u16(packet, udpOffset + 2) != DESTINATION_PORT) return null
        val payloadOffset = udpOffset + 8
        if (u32(packet, payloadOffset) != MAGIC) return null
        return Probe(u32(packet, payloadOffset + 4))
    }

    private fun u16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xff) shl 8) or (data[offset + 1].toInt() and 0xff)

    private fun u32(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xff) shl 24) or
            ((data[offset + 1].toInt() and 0xff) shl 16) or
            ((data[offset + 2].toInt() and 0xff) shl 8) or
            (data[offset + 3].toInt() and 0xff)
}
