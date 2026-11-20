package com.firewalldns.diagnostics

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class FirewallDnsTrafficClassifierTest {
    @Test fun identifiesDnsUdpAsConfirmed() {
        val payload = ByteArray(12)
        val result = FirewallDnsTrafficClassifier.classify(ipv4Udp(53000, 53, payload))
        assertEquals("IPv4", result.network)
        assertEquals("UDP", result.transport)
        assertEquals("DNS", result.application)
        assertEquals(FirewallDnsTrafficClassifier.Certainty.CONFIRMED, result.certainty)
    }

    @Test fun identifiesPlainHttpByPayloadNotPort() {
        val result = FirewallDnsTrafficClassifier.classify(
            ipv4Tcp(51000, 8080, "GET / HTTP/1.1\r\n".toByteArray()),
        )
        assertEquals("HTTP", result.application)
        assertEquals(FirewallDnsTrafficClassifier.Certainty.CONFIRMED, result.certainty)
    }

    @Test fun port443AloneDoesNotClaimHttps() {
        val result = FirewallDnsTrafficClassifier.classify(ipv4Tcp(51000, 443, byteArrayOf(1, 2, 3, 4)))
        assertEquals("TCP_443_UNKNOWN", result.application)
        assertEquals(FirewallDnsTrafficClassifier.Certainty.PORT_ONLY, result.certainty)
    }

    @Test fun recognizesTlsRecordOn443AsCandidateOnly() {
        val tls = byteArrayOf(22, 3, 3, 0, 4, 1, 0, 0, 0)
        val result = FirewallDnsTrafficClassifier.classify(ipv4Tcp(51000, 443, tls))
        assertEquals("TLS_HTTPS_CANDIDATE", result.application)
        assertEquals(FirewallDnsTrafficClassifier.Certainty.LIKELY, result.certainty)
    }

    @Test fun recognizesQuicLongHeaderOnUdp443() {
        val quic = byteArrayOf(0xc0.toByte(), 0, 0, 0, 1, 0)
        val result = FirewallDnsTrafficClassifier.classify(ipv4Udp(51000, 443, quic))
        assertEquals("QUIC", result.application)
        assertEquals(FirewallDnsTrafficClassifier.Certainty.CONFIRMED, result.certainty)
    }

    @Test fun tcp853WithoutTlsSignatureIsOnlyDotPortCandidate() {
        val result = FirewallDnsTrafficClassifier.classify(ipv4Tcp(51000, 853, byteArrayOf(1, 2, 3, 4)))
        assertEquals("DOT_PORT_CANDIDATE", result.application)
        assertEquals(FirewallDnsTrafficClassifier.Certainty.PORT_ONLY, result.certainty)
        assertEquals("dot_port_without_tls_signature", result.reason)
    }

    @Test fun udp443WithoutQuicSignatureIsNotCalledQuic() {
        val result = FirewallDnsTrafficClassifier.classify(ipv4Udp(51000, 443, byteArrayOf(1, 2, 3, 4)))
        assertEquals("UDP_443_UNKNOWN", result.application)
        assertEquals(FirewallDnsTrafficClassifier.Certainty.PORT_ONLY, result.certainty)
    }

    @Test fun identifiesDotOnlyAsCandidate() {
        val tls = byteArrayOf(22, 3, 3, 0, 4, 1, 0, 0, 0)
        val result = FirewallDnsTrafficClassifier.classify(ipv4Tcp(51000, 853, tls))
        assertEquals("DOT_CANDIDATE", result.application)
        assertEquals(FirewallDnsTrafficClassifier.Certainty.LIKELY, result.certainty)
    }

    @Test fun reportsFragmentsWithoutGuessingTransportPayload() {
        val packet = ipv4Udp(51000, 443, byteArrayOf(1, 2, 3, 4))
        packet[6] = 0x20
        val result = FirewallDnsTrafficClassifier.classify(packet)
        assertTrueFragment(result.fragmented)
        assertEquals("FRAGMENT", result.application)
    }

    @Test fun rejectsTruncatedAndUnknownPacketsSafely() {
        assertEquals("ipv4_header_truncated",
            FirewallDnsTrafficClassifier.classify(byteArrayOf(0x45)).reason)
        assertEquals("unsupported_ip_version",
            FirewallDnsTrafficClassifier.classify(byteArrayOf(0x10)).reason)
    }

    @Test fun doesNotExposePayloadOrDomainInResult() {
        val result = FirewallDnsTrafficClassifier.classify(
            ipv4Tcp(51000, 80, "GET /secret HTTP/1.1".toByteArray()),
        )
        assertEquals("HTTP", result.application)
        assertFalse(result.toString().contains("secret"))
    }

    private fun assertTrueFragment(value: Boolean) { org.junit.Assert.assertTrue(value) }

    private fun ipv4Udp(source: Int, destination: Int, payload: ByteArray): ByteArray {
        val udp = ByteArray(8 + payload.size)
        put16(udp, 0, source); put16(udp, 2, destination); put16(udp, 4, udp.size)
        payload.copyInto(udp, 8)
        return ipv4(17, udp)
    }

    private fun ipv4Tcp(source: Int, destination: Int, payload: ByteArray): ByteArray {
        val tcp = ByteArray(20 + payload.size)
        put16(tcp, 0, source); put16(tcp, 2, destination); tcp[12] = 0x50
        payload.copyInto(tcp, 20)
        return ipv4(6, tcp)
    }

    private fun ipv4(protocol: Int, payload: ByteArray): ByteArray {
        val packet = ByteArray(20 + payload.size)
        packet[0] = 0x45; put16(packet, 2, packet.size); packet[8] = 64; packet[9] = protocol.toByte()
        packet[12] = 10; packet[15] = 1; packet[16] = 10; packet[19] = 2
        payload.copyInto(packet, 20)
        return packet
    }

    private fun put16(target: ByteArray, offset: Int, value: Int) {
        target[offset] = (value ushr 8).toByte()
        target[offset + 1] = value.toByte()
    }
}
