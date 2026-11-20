package com.firewalldns.diagnostics

/**
 * Passive, privacy-preserving classifier for a single complete IP packet.
 *
 * It never changes or forwards traffic. Classifications are layered: an IP
 * packet may have both a transport and an application-protocol label.
 * Port numbers alone are not treated as proof of an application protocol.
 */
object FirewallDnsTrafficClassifier {
    enum class Certainty { CONFIRMED, LIKELY, PORT_ONLY, UNKNOWN }

    data class Classification(
        val network: String,
        val transport: String,
        val application: String,
        val certainty: Certainty,
        val sourcePort: Int? = null,
        val destinationPort: Int? = null,
        val fragmented: Boolean = false,
        val reason: String,
    )

    fun classify(packet: ByteArray): Classification {
        if (packet.isEmpty()) return unknown("empty_packet")
        return when ((packet[0].toInt() ushr 4) and 0x0f) {
            4 -> classifyIpv4(packet)
            6 -> classifyIpv6(packet)
            else -> unknown("unsupported_ip_version")
        }
    }

    private fun classifyIpv4(p: ByteArray): Classification {
        if (p.size < 20) return unknown("ipv4_header_truncated")
        val ihl = (p[0].toInt() and 0x0f) * 4
        val total = u16(p, 2)
        if (ihl < 20 || ihl > p.size || total < ihl || total > p.size) {
            return unknown("ipv4_length_invalid")
        }
        val fragment = u16(p, 6)
        val fragmented = (fragment and 0x3fff) != 0
        val proto = p[9].toInt() and 0xff
        return classifyTransport("IPv4", proto, p, ihl, total, fragmented)
    }

    private fun classifyIpv6(p: ByteArray): Classification {
        if (p.size < 40) return unknown("ipv6_header_truncated")
        val payloadLength = u16(p, 4)
        val end = 40 + payloadLength
        if (payloadLength == 0 || end > p.size) return unknown("ipv6_payload_length_invalid")
        var next = p[6].toInt() and 0xff
        var offset = 40
        var fragmented = false
        var extensions = 0
        while (next in IPV6_EXTENSION_HEADERS) {
            if (++extensions > 8) return unknown("ipv6_extension_chain_too_long")
            if (next == 44) {
                if (offset + 8 > end) return unknown("ipv6_fragment_header_truncated")
                val fragmentBits = u16(p, offset + 2)
                fragmented = (fragmentBits and 0xfff9) != 0
                next = p[offset].toInt() and 0xff
                offset += 8
                if (fragmented) {
                    return Classification("IPv6", transportName(next), "FRAGMENT", Certainty.CONFIRMED,
                        fragmented = true, reason = "ipv6_fragment_requires_reassembly")
                }
                continue
            }
            if (offset + 2 > end) return unknown("ipv6_extension_header_truncated")
            val following = p[offset].toInt() and 0xff
            val length = if (next == 51) ((p[offset + 1].toInt() and 0xff) + 2) * 4
                         else ((p[offset + 1].toInt() and 0xff) + 1) * 8
            if (length < 8 || offset + length > end) return unknown("ipv6_extension_length_invalid")
            next = following
            offset += length
        }
        return classifyTransport("IPv6", next, p, offset, end, fragmented)
    }

    private fun classifyTransport(
        network: String, protocol: Int, p: ByteArray, offset: Int, end: Int, fragmented: Boolean,
    ): Classification {
        val transport = transportName(protocol)
        if (fragmented) return Classification(network, transport, "FRAGMENT", Certainty.CONFIRMED,
            fragmented = true, reason = "ip_fragment_not_reassembled")
        if (protocol == 1 || protocol == 58) {
            return Classification(network, transport, "ICMP", Certainty.CONFIRMED, reason = "ip_protocol_number")
        }
        if (protocol != 6 && protocol != 17) {
            return Classification(network, transport, "OTHER_IP", Certainty.CONFIRMED, reason = "ip_protocol_number")
        }
        val minimum = if (protocol == 6) 20 else 8
        if (offset + minimum > end) return Classification(network, transport, "MALFORMED", Certainty.UNKNOWN,
            reason = "transport_header_truncated")
        val source = u16(p, offset)
        val destination = u16(p, offset + 2)
        val payloadOffset: Int
        if (protocol == 6) {
            val headerLength = ((p[offset + 12].toInt() ushr 4) and 0x0f) * 4
            if (headerLength < 20 || offset + headerLength > end) {
                return Classification(network, transport, "MALFORMED", Certainty.UNKNOWN,
                    sourcePort = source, destinationPort = destination, reason = "tcp_header_length_invalid")
            }
            payloadOffset = offset + headerLength
        } else {
            val udpLength = u16(p, offset + 4)
            if (udpLength < 8 || offset + udpLength > end) {
                return Classification(network, transport, "MALFORMED", Certainty.UNKNOWN,
                    sourcePort = source, destinationPort = destination, reason = "udp_length_invalid")
            }
            payloadOffset = offset + 8
        }
        val payloadEnd = if (protocol == 17) offset + u16(p, offset + 4) else end
        return classifyApplication(network, transport, source, destination, p, payloadOffset, payloadEnd)
    }

    private fun classifyApplication(
        network: String, transport: String, source: Int, destination: Int,
        p: ByteArray, start: Int, end: Int,
    ): Classification {
        val size = end - start
        fun result(app: String, certainty: Certainty, reason: String) =
            Classification(network, transport, app, certainty, source, destination, reason = reason)

        if (source == 53 || destination == 53) {
            return if (size >= 12) result("DNS", Certainty.CONFIRMED, "dns_port_and_header_length")
                   else result("DNS_CANDIDATE", Certainty.PORT_ONLY, "dns_port_without_complete_header")
        }
        if (transport == "TCP" && looksLikeHttp(p, start, end)) {
            return result("HTTP", Certainty.CONFIRMED, "plaintext_http_method_signature")
        }
        if (transport == "TCP" && looksLikeTls(p, start, end)) {
            return when {
                source == 853 || destination == 853 ->
                    result("DOT_CANDIDATE", Certainty.LIKELY, "tls_record_on_dot_port")
                source == 443 || destination == 443 ->
                    result("TLS_HTTPS_CANDIDATE", Certainty.LIKELY, "tls_record_on_https_port_encrypted_content")
                else -> result("TLS", Certainty.CONFIRMED, "tls_record_signature")
            }
        }
        if (transport == "UDP" && (source == 443 || destination == 443) && looksLikeQuicLongHeader(p, start, end)) {
            return result("QUIC", Certainty.CONFIRMED, "quic_long_header_signature")
        }
        if ((source == 853 || destination == 853) && transport == "TCP") {
            return result("DOT_PORT_CANDIDATE", Certainty.PORT_ONLY, "dot_port_without_tls_signature")
        }
        if ((source == 443 || destination == 443) && transport == "UDP") {
            return result("UDP_443_UNKNOWN", Certainty.PORT_ONLY, "udp_443_is_not_proof_of_quic")
        }
        if ((source == 443 || destination == 443) && transport == "TCP") {
            return result("TCP_443_UNKNOWN", Certainty.PORT_ONLY, "tcp_443_is_not_proof_of_tls")
        }
        return result("UNKNOWN", Certainty.UNKNOWN, "no_supported_payload_signature")
    }

    private fun looksLikeHttp(p: ByteArray, start: Int, end: Int): Boolean {
        val methods = arrayOf("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ")
        return methods.any { method -> asciiStartsWith(p, start, end, method) }
    }

    private fun looksLikeTls(p: ByteArray, start: Int, end: Int): Boolean {
        if (end - start < 5) return false
        val type = p[start].toInt() and 0xff
        val major = p[start + 1].toInt() and 0xff
        val minor = p[start + 2].toInt() and 0xff
        val length = u16(p, start + 3)
        return type in 20..23 && major == 3 && minor in 1..4 && length > 0 && length <= 18_432
    }

    private fun looksLikeQuicLongHeader(p: ByteArray, start: Int, end: Int): Boolean {
        if (end - start < 6) return false
        val first = p[start].toInt() and 0xff
        val version = ((p[start + 1].toInt() and 0xff) shl 24) or
            ((p[start + 2].toInt() and 0xff) shl 16) or
            ((p[start + 3].toInt() and 0xff) shl 8) or (p[start + 4].toInt() and 0xff)
        return (first and 0xc0) == 0xc0 && version != 0
    }

    private fun asciiStartsWith(p: ByteArray, start: Int, end: Int, value: String): Boolean {
        if (end - start < value.length) return false
        for (i in value.indices) if ((p[start + i].toInt() and 0xff) != value[i].code) return false
        return true
    }

    private fun u16(p: ByteArray, offset: Int): Int =
        ((p[offset].toInt() and 0xff) shl 8) or (p[offset + 1].toInt() and 0xff)

    private fun transportName(protocol: Int): String = when (protocol) {
        6 -> "TCP"
        17 -> "UDP"
        1, 58 -> "ICMP"
        else -> "OTHER"
    }

    private fun unknown(reason: String) =
        Classification("UNKNOWN", "UNKNOWN", "UNKNOWN", Certainty.UNKNOWN, reason = reason)

    private val IPV6_EXTENSION_HEADERS = setOf(0, 43, 44,  AH, 60)
    private const val AH = 51
}
