package com.firewalldns.engine.android

/**
 * Narrow ingress gate for the production smoltcp DNS/TCP listener.
 *
 * Only complete, unfragmented-at-this-stage IPv4/IPv6 TCP packets addressed
 * to port 53 are handed to smoltcp. IP fragments must already have been
 * reassembled by [IpFragmentReassembler]. IPv6 extension-header chains are
 * deliberately not classified as TCP until their parser is covered.
 *
 * smoltcp remains responsible for TCP state, sequence numbers and checksums.
 */
object DnsTcpPacketClassifier {
    fun isClientDnsTcpPacket(packet: ByteArray): Boolean {
        if (packet.isEmpty()) return false
        return when ((packet[0].toInt() ushr 4) and 0x0f) {
            IPV4 -> isIpv4DnsTcp(packet)
            IPV6 -> isIpv6DnsTcp(packet)
            else -> false
        }
    }

    private fun isIpv4DnsTcp(packet: ByteArray): Boolean {
        if (packet.size < IPV4_MIN_HEADER) return false
        val ipHeaderLength = (packet[0].toInt() and 0x0f) * 4
        val totalLength = u16(packet, 2)
        if (ipHeaderLength !in IPV4_MIN_HEADER..IPV4_MAX_HEADER) return false
        if (totalLength < ipHeaderLength + TCP_MIN_HEADER || totalLength > packet.size) return false
        if ((packet[9].toInt() and 0xff) != IPPROTO_TCP) return false

        // The service reassembles fragments before classification. A fragment
        // that survives that stage must never be passed as a complete TCP flow.
        if ((u16(packet, 6) and IPV4_FRAGMENT_MASK) != 0) return false
        return hasDnsTcpHeader(packet, ipHeaderLength, totalLength)
    }

    private fun isIpv6DnsTcp(packet: ByteArray): Boolean {
        if (packet.size < IPV6_HEADER + TCP_MIN_HEADER) return false
        // Extension headers are intentionally not accepted by this narrow gate.
        if ((packet[6].toInt() and 0xff) != IPPROTO_TCP) return false
        val payloadLength = u16(packet, 4)
        if (payloadLength < TCP_MIN_HEADER) return false
        val totalLength = IPV6_HEADER + payloadLength
        if (totalLength > packet.size) return false
        return hasDnsTcpHeader(packet, IPV6_HEADER, totalLength)
    }

    private fun hasDnsTcpHeader(packet: ByteArray, offset: Int, totalLength: Int): Boolean {
        if (offset < 0 || offset + TCP_MIN_HEADER > totalLength) return false
        val destinationPort = u16(packet, offset + 2)
        val tcpHeaderLength = ((packet[offset + 12].toInt() ushr 4) and 0x0f) * 4
        if (tcpHeaderLength !in TCP_MIN_HEADER..TCP_MAX_HEADER) return false
        if (offset + tcpHeaderLength > totalLength) return false
        return destinationPort == DNS_PORT
    }

    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private const val IPV4 = 4
    private const val IPV6 = 6
    private const val IPV4_MIN_HEADER = 20
    private const val IPV4_MAX_HEADER = 60
    private const val IPV6_HEADER = 40
    private const val TCP_MIN_HEADER = 20
    private const val TCP_MAX_HEADER = 60
    private const val IPV4_FRAGMENT_MASK = 0xbfff
    private const val IPPROTO_TCP = 6
    private const val DNS_PORT = 53
}
