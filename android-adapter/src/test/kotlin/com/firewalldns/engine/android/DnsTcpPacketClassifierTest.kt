package com.firewalldns.engine.android

import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsTcpPacketClassifierTest {

    @Test
    fun acceptsCompleteIpv4DnsTcpPacket() {
        assertTrue(DnsTcpPacketClassifier.isClientDnsTcpPacket(ipv4Tcp(destinationPort = 53)))
    }

    @Test
    fun acceptsCompleteIpv6DnsTcpPacket() {
        assertTrue(DnsTcpPacketClassifier.isClientDnsTcpPacket(ipv6Tcp(destinationPort = 53)))
    }

    @Test
    fun acceptsIpv4OptionsWhenTcpHeaderFitsDeclaredLength() {
        val packet = ByteArray(44)
        packet[0] = 0x46
        putU16(packet, 2, packet.size)
        packet[9] = 6
        putU16(packet, 26, 53)
        packet[36] = 0x50
        assertTrue(DnsTcpPacketClassifier.isClientDnsTcpPacket(packet))
    }

    @Test
    fun rejectsNonDnsTcpAndNonTcpPackets() {
        assertFalse(DnsTcpPacketClassifier.isClientDnsTcpPacket(ipv4Tcp(destinationPort = 443)))
        val udp = ipv4Tcp(destinationPort = 53).also { it[9] = 17 }
        assertFalse(DnsTcpPacketClassifier.isClientDnsTcpPacket(udp))
    }

    @Test
    fun rejectsTruncatedDeclaredIpLengthAndShortTcpHeader() {
        val truncated = ipv4Tcp(destinationPort = 53).also { putU16(it, 2, 39) }
        assertFalse(DnsTcpPacketClassifier.isClientDnsTcpPacket(truncated))

        val shortTcp = ipv4Tcp(destinationPort = 53).also { it[32] = 0x40 }
        assertFalse(DnsTcpPacketClassifier.isClientDnsTcpPacket(shortTcp))

        val truncatedV6 = ipv6Tcp(destinationPort = 53).also { putU16(it, 4, 19) }
        assertFalse(DnsTcpPacketClassifier.isClientDnsTcpPacket(truncatedV6))
    }

    @Test
    fun rejectsFragmentsAndIpv6ExtensionHeaders() {
        val fragment = ipv4Tcp(destinationPort = 53).also { putU16(it, 6, 0x2000) }
        assertFalse(DnsTcpPacketClassifier.isClientDnsTcpPacket(fragment))
        val reservedFlag = ipv4Tcp(destinationPort = 53).also { putU16(it, 6, 0x8000) }
        assertFalse(DnsTcpPacketClassifier.isClientDnsTcpPacket(reservedFlag))

        val extension = ipv6Tcp(destinationPort = 53).also { it[6] = 0 }
        assertFalse(DnsTcpPacketClassifier.isClientDnsTcpPacket(extension))
    }

    private fun ipv4Tcp(destinationPort: Int): ByteArray = ByteArray(40).also {
        it[0] = 0x45
        putU16(it, 2, it.size)
        it[9] = 6
        putU16(it, 20, 49152)
        putU16(it, 22, destinationPort)
        it[32] = 0x50
    }

    private fun ipv6Tcp(destinationPort: Int): ByteArray = ByteArray(60).also {
        it[0] = 0x60
        putU16(it, 4, 20)
        it[6] = 6
        putU16(it, 40, 49152)
        putU16(it, 42, destinationPort)
        it[52] = 0x50
    }

    private fun putU16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 8).toByte()
        bytes[offset + 1] = value.toByte()
    }
}
