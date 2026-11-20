package com.firewalldns.diagnostics

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FirewallDnsDiagnosticMetricsTest {
    @Test fun aggregatesProtocolLabelsWithoutRetainingPayload() {
        val metrics = FirewallDnsDiagnosticMetrics()
        val payload = ByteArray(12)
        val packet = ipv4Udp(53000, 53, payload)
        metrics.record(packet, packet.size)
        val json = metrics.snapshotJson()

        assertTrue(json.contains("\"packets_classified\": 1"))
        assertTrue(json.contains("\"bytes_classified\": ${packet.size}"))
        assertTrue(json.contains("\"UDP\": 1"))
        assertTrue(json.contains("\"DNS\": 1"))
        assertTrue(json.contains("\"CONFIRMED\": 1"))
        assertTrue(!json.contains("example.com"))
    }

    @Test fun countsTcpAndUdpSeparatelyAndBoundsLatencySamples() {
        val metrics = FirewallDnsDiagnosticMetrics()
        val udp = ipv4Udp(53000, 443, byteArrayOf(1, 2, 3, 4))
        val tcp = ipv4Tcp(53000, 443, byteArrayOf(1, 2, 3, 4))
        metrics.record(udp, udp.size)
        metrics.record(tcp, tcp.size)

        val json = metrics.snapshotJson()
        assertTrue(json.contains("\"UDP\": 1"))
        assertTrue(json.contains("\"TCP\": 1"))
        assertTrue(json.contains("\"samples\": 2"))
    }

    @Test fun recordsProcessingFailuresByCause() {\n        val metrics = FirewallDnsDiagnosticMetrics()\n        metrics.recordProcessingOutcome("queue_rejected")\n        metrics.recordProcessingOutcome("response_write_failed")\n        val json = metrics.snapshotJson()\n        assertTrue(json.contains("\\\"queue_rejected\\\": 1"))\n        assertTrue(json.contains("\\\"response_write_failed\\\": 1"))\n    }\n\n    @Test fun resetClearsAllCountersAndSamples() {
        val metrics = FirewallDnsDiagnosticMetrics()
        val packet = ipv4Udp(53000, 53, ByteArray(12))
        metrics.record(packet, packet.size)
        metrics.reset()
        val json = metrics.snapshotJson()

        assertTrue(json.contains("\"packets_classified\": 0"))
        assertTrue(json.contains("\"samples\": 0"))
        assertEquals("{}", json.substringAfter("\"by_transport\": ").substringBefore(","))
    }

    private fun ipv4Udp(source: Int, destination: Int, payload: ByteArray): ByteArray {
        val packet = ByteArray(28 + payload.size)
        packet[0] = 0x45
        put16(packet, 2, packet.size)
        packet[8] = 64
        packet[9] = 17
        packet[12] = 10; packet[15] = 1
        packet[16] = 10; packet[19] = 2
        put16(packet, 20, source)
        put16(packet, 22, destination)
        put16(packet, 24, 8 + payload.size)
        payload.copyInto(packet, 28)
        return packet
    }

    private fun ipv4Tcp(source: Int, destination: Int, payload: ByteArray): ByteArray {
        val packet = ByteArray(40 + payload.size)
        packet[0] = 0x45
        put16(packet, 2, packet.size)
        packet[8] = 64
        packet[9] = 6
        packet[12] = 10; packet[15] = 1
        packet[16] = 10; packet[19] = 2
        put16(packet, 20, source)
        put16(packet, 22, destination)
        packet[32] = 0x50
        payload.copyInto(packet, 40)
        return packet
    }

    private fun put16(target: ByteArray, offset: Int, value: Int) {
        target[offset] = (value ushr 8).toByte()
        target[offset + 1] = value.toByte()
    }
}
