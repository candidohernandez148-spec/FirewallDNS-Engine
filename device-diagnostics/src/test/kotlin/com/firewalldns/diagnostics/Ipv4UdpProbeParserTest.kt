package com.firewalldns.diagnostics

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class Ipv4UdpProbeParserTest {
    @Test fun parsesValidProbeWithOptions() {
        val packet = packet(24)
        assertEquals(ProbeExpected(17), Ipv4UdpProbeParser.parse(packet, packet.size)?.let { ProbeExpected(it.sequence) })
    }

    @Test fun rejectsTruncatedAndInvalidHeaders() {
        val packet = packet(20)
        assertNull(Ipv4UdpProbeParser.parse(packet, 19))
        packet[0] = 0x65
        assertNull(Ipv4UdpProbeParser.parse(packet, packet.size))
    }

    @Test fun rejectsWrongDestinationProtocolPortAndMagic() {
        val wrongDestination = packet(20).also { it[19] = 2 }
        assertNull(Ipv4UdpProbeParser.parse(wrongDestination, wrongDestination.size))
        val wrongProtocol = packet(20).also { it[9] = 6 }
        assertNull(Ipv4UdpProbeParser.parse(wrongProtocol, wrongProtocol.size))
        val wrongPort = packet(20).also { it[22] = 0; it[23] = 53 }
        assertNull(Ipv4UdpProbeParser.parse(wrongPort, wrongPort.size))
        val wrongMagic = packet(20).also { it[28] = 0 }
        assertNull(Ipv4UdpProbeParser.parse(wrongMagic, wrongMagic.size))
    }

    @Test fun reportsHeaderOnlyRejectionMetadata() {
        val packet = packet(20).also { it[19] = 2 }
        val inspection = Ipv4UdpProbeParser.inspect(packet, packet.size)
        assertNull(inspection.probe)
        assertEquals("wrong_destination", inspection.rejection)
        assertEquals(4, inspection.ipVersion)
        assertEquals(17, inspection.protocol)
        assertEquals("198.18.0.2", inspection.destinationIpv4)
        assertEquals(4242, inspection.destinationPort)
        assertEquals(16, inspection.udpLength)
    }

    @Test fun reportsNonIpv4PacketsWithoutReadingPayload() {
        val packet = ByteArray(48).also { it[0] = 0x60 }
        val inspection = Ipv4UdpProbeParser.inspect(packet, packet.size)
        assertEquals("not_ipv4", inspection.rejection)
        assertEquals(6, inspection.ipVersion)
        assertNull(inspection.destinationIpv4)
    }

    @Test fun rejectsInvalidLengthsAndFragments() {
        val shortUdp = packet(20).also { it[25] = 7 }
        assertNull(Ipv4UdpProbeParser.parse(shortUdp, shortUdp.size))
        val fragment = packet(20).also { it[6] = 0x20 }
        assertNull(Ipv4UdpProbeParser.parse(fragment, fragment.size))
        val oversizedTotal = packet(20).also { it[2] = 1; it[3] = 0 }
        assertNull(Ipv4UdpProbeParser.parse(oversizedTotal, oversizedTotal.size))
    }

    private fun packet(headerLength: Int): ByteArray {
        val bytes = ByteArray(headerLength + 16)
        bytes[0] = ((4 shl 4) or (headerLength / 4)).toByte()
        bytes[2] = 0
        bytes[3] = bytes.size.toByte()
        bytes[9] = 17
        bytes[16] = 198.toByte()
        bytes[17] = 18
        bytes[18] = 0
        bytes[19] = 1
        bytes[headerLength + 2] = 0x10
        bytes[headerLength + 3] = 0x92.toByte() // 4242
        bytes[headerLength + 4] = 0
        bytes[headerLength + 5] = 16
        writeInt(bytes, headerLength + 8, Ipv4UdpProbeParser.MAGIC)
        writeInt(bytes, headerLength + 12, 17)
        return bytes
    }

    private fun writeInt(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 24).toByte()
        bytes[offset + 1] = (value ushr 16).toByte()
        bytes[offset + 2] = (value ushr 8).toByte()
        bytes[offset + 3] = value.toByte()
    }

    private data class ProbeExpected(val sequence: Int)
}
