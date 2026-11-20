package com.firewalldns.engine.android

import com.firewalldns.engine.dns.DnsSocketProtector
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidUdpTunBridgeTest {
    @Test
    fun protectedLoopbackFlowReturnsSynthesizedIpv4PacketToTun() {
        DatagramSocket(0, InetAddress.getLoopbackAddress()).use { peer ->
            peer.soTimeout = 2_000
            val server = Thread {
                val incoming = DatagramPacket(ByteArray(128), 128)
                peer.receive(incoming)
                assertArrayEquals(
                    "firewalldns-udp-request".toByteArray(),
                    incoming.data.copyOfRange(incoming.offset, incoming.offset + incoming.length),
                )
                val reply = "firewalldns-udp-response".toByteArray()
                peer.send(DatagramPacket(reply, reply.size, incoming.address, incoming.port))
            }.apply { isDaemon = true; start() }

            val responseReady = CountDownLatch(1)
            val response = AtomicReference<ByteArray>()
            val bridge = newBridge(
                writeTunPacket = {
                    response.set(it)
                    responseReady.countDown()
                },
                mapRemoteEndpoint = {
                    InetSocketAddress(InetAddress.getLoopbackAddress(), peer.localPort)
                },
            )
            try {
                val request = ipv4UdpPacket(
                    source = byteArrayOf(10, 77, 0, 2),
                    destination = byteArrayOf(198, 18, 0, 1),
                    sourcePort = 53000,
                    destinationPort = 443,
                    payload = "firewalldns-udp-request".toByteArray(),
                )
                assertEquals(UdpTunPacketResult.QUEUED, bridge.process(request))
                assertTrue("TUN response was not produced", responseReady.await(2, TimeUnit.SECONDS))
                server.join(2_000)
                val decoded = UdpTunPacketCodec.parse(response.get())
                assertNotNull(decoded)
                assertEquals("198.18.0.1", decoded!!.sourceAddress.hostAddress)
                assertEquals("10.77.0.2", decoded.destinationAddress.hostAddress)
                assertEquals(443, decoded.sourcePort)
                assertEquals(53000, decoded.destinationPort)
                assertArrayEquals("firewalldns-udp-response".toByteArray(), decoded.payload)
            } finally {
                bridge.close()
            }
            assertEquals(0, bridge.activeFlowCount)
        }
    }

    @Test
    fun leavesDnsPacketsForExistingDnsProcessor() {
        val bridge = newBridge(writeTunPacket = {})
        try {
            val dns = ipv4UdpPacket(
                byteArrayOf(10, 77, 0, 2),
                byteArrayOf(10, 77, 0, 1),
                53000,
                53,
                byteArrayOf(1, 2, 3, 4),
            )
            assertEquals(UdpTunPacketResult.DNS_BYPASS, bridge.process(dns))
            assertEquals(0, bridge.activeFlowCount)
        } finally {
            bridge.close()
        }
    }

    @Test
    fun rejectsFragmentedIpv4InsteadOfForwardingPartialDatagram() {
        val packet = ipv4UdpPacket(
            byteArrayOf(10, 77, 0, 2),
            byteArrayOf(198, 18, 0, 1),
            53000,
            443,
            byteArrayOf(1, 2, 3),
        )
        packet[6] = 0x20
        packet[7] = 0
        putU16(packet, 10, 0)
        putU16(packet, 10, checksum(packet, 0, 20))
        val bridge = newBridge(writeTunPacket = {})
        try {
            assertEquals(UdpTunPacketResult.UNSUPPORTED, bridge.process(packet))
            assertEquals(0, bridge.activeFlowCount)
        } finally {
            bridge.close()
        }
    }

    @Test
    fun parsesAndBuildsIpv6UdpResponseWithMandatoryChecksum() {
        val request = ipv6UdpPacket(
            source = InetAddress.getByName("fd77::2").address,
            destination = InetAddress.getByName("2001:db8::1").address,
            sourcePort = 53001,
            destinationPort = 443,
            payload = "ipv6-request".toByteArray(),
        )
        val decodedRequest = UdpTunPacketCodec.parse(request)
        assertNotNull(decodedRequest)
        val response = UdpTunPacketCodec.buildResponse(decodedRequest!!, "ipv6-response".toByteArray())
        assertNotNull(response)
        val decodedResponse = UdpTunPacketCodec.parse(response!!)
        assertNotNull(decodedResponse)
        assertEquals("2001:db8:0:0:0:0:0:1", decodedResponse!!.sourceAddress.hostAddress)
        assertEquals("fd77:0:0:0:0:0:0:2", decodedResponse.destinationAddress.hostAddress)
        assertArrayEquals("ipv6-response".toByteArray(), decodedResponse.payload)
        assertNull(UdpTunPacketCodec.parse(response.copyOfRange(0, response.size - 1)))
    }

    private fun newBridge(
        writeTunPacket: (ByteArray) -> Unit,
        mapRemoteEndpoint: (InetSocketAddress) -> InetSocketAddress = { it },
    ): AndroidUdpTunBridge {
        val protector = object : DnsSocketProtector {
            override fun protect(socket: DatagramSocket): Boolean = true
            override fun protect(socket: Socket): Boolean = true
        }
        val manager = AndroidUdpFlowManager(
            socketFactory = AndroidProtectedUdpSocketFactory(protector),
            maxFlows = 2,
            maxQueuedDatagramsPerFlow = 4,
            maxDatagramBytes = 1_024,
            maxQueuedBytesPerFlow = 4_096,
            receivePollTimeoutMillis = 25,
        )
        return AndroidUdpTunBridge(manager, writeTunPacket, mapRemoteEndpoint)
    }

    private fun ipv4UdpPacket(
        source: ByteArray,
        destination: ByteArray,
        sourcePort: Int,
        destinationPort: Int,
        payload: ByteArray,
    ): ByteArray {
        val packet = ByteArray(20 + 8 + payload.size)
        packet[0] = 0x45
        putU16(packet, 2, packet.size)
        putU16(packet, 4, 7)
        putU16(packet, 6, 0x4000)
        packet[8] = 64
        packet[9] = 17
        source.copyInto(packet, 12)
        destination.copyInto(packet, 16)
        putU16(packet, 20, sourcePort)
        putU16(packet, 22, destinationPort)
        putU16(packet, 24, 8 + payload.size)
        payload.copyInto(packet, 28)
        putU16(packet, 10, checksum(packet, 0, 20))
        return packet
    }

    private fun ipv6UdpPacket(
        source: ByteArray,
        destination: ByteArray,
        sourcePort: Int,
        destinationPort: Int,
        payload: ByteArray,
    ): ByteArray {
        val packet = ByteArray(40 + 8 + payload.size)
        packet[0] = 0x60
        putU16(packet, 4, 8 + payload.size)
        packet[6] = 17
        packet[7] = 64
        source.copyInto(packet, 8)
        destination.copyInto(packet, 24)
        putU16(packet, 40, sourcePort)
        putU16(packet, 42, destinationPort)
        putU16(packet, 44, 8 + payload.size)
        payload.copyInto(packet, 48)
        putU16(packet, 46, udpChecksum(source, destination, packet, 40, 8 + payload.size, true))
        return packet
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
            sum += 17
        } else {
            sum += 17
            sum += length.toLong()
        }
        var index = offset
        val end = offset + length
        while (index + 1 < end) {
            sum += (((packet[index].toInt() and 0xff) shl 8) or (packet[index + 1].toInt() and 0xff)).toLong()
            index += 2
        }
        if (index < end) sum += ((packet[index].toInt() and 0xff) shl 8).toLong()
        while ((sum ushr 16) != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.toInt().inv() and 0xffff
    }

    private fun checksum(packet: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var index = offset
        val end = offset + length
        while (index + 1 < end) {
            sum += (((packet[index].toInt() and 0xff) shl 8) or (packet[index + 1].toInt() and 0xff)).toLong()
            index += 2
        }
        if (index < end) sum += ((packet[index].toInt() and 0xff) shl 8).toLong()
        while ((sum ushr 16) != 0L) sum = (sum and 0xffff) + (sum ushr 16)
        return sum.toInt().inv() and 0xffff
    }

    private fun putU16(packet: ByteArray, offset: Int, value: Int) {
        packet[offset] = (value ushr 8).toByte()
        packet[offset + 1] = value.toByte()
    }
}
