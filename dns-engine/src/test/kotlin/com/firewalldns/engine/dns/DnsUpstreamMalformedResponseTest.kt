package com.firewalldns.engine.dns

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class DnsUpstreamMalformedResponseTest {
    @Test
    fun rejectsTruncatedUpstreamDnsHeader() {
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { server ->
            server.soTimeout = 2_000
            val query = query()
            val responder = thread {
                val incoming = DatagramPacket(ByteArray(512), 512)
                server.receive(incoming)
                val malformed = ByteArray(11)
                server.send(DatagramPacket(malformed, malformed.size, incoming.socketAddress))
            }
            val result = DnsUpstreamClient(
                DnsUpstreamConfig("127.0.0.1", server.localPort, timeoutMillis = 2_000),
                AllowSocketProtection,
            ).exchange(query)
            responder.join(2_000)
            assertEquals(
                "dns_upstream_response_header_truncated",
                assertIs<DnsUpstreamResult.Failure>(result).reason,
            )
        }
    }

    @Test
    fun rejectsUpstreamPacketThatIsNotMarkedAsResponse() {
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { server ->
            server.soTimeout = 2_000
            val query = query()
            val responder = thread {
                val incoming = DatagramPacket(ByteArray(512), 512)
                server.receive(incoming)
                val malformed = query.copyOf()
                server.send(DatagramPacket(malformed, malformed.size, incoming.socketAddress))
            }
            val result = DnsUpstreamClient(
                DnsUpstreamConfig("127.0.0.1", server.localPort, timeoutMillis = 2_000),
                AllowSocketProtection,
            ).exchange(query)
            responder.join(2_000)
            assertEquals(
                "dns_upstream_packet_is_not_response",
                assertIs<DnsUpstreamResult.Failure>(result).reason,
            )
        }
    }

    private fun query(): ByteArray {
        val question = byteArrayOf(1, 'a'.code.toByte(), 0, 0, 1, 0, 1)
        return ByteArray(12).also {
            it[0] = 0x12
            it[1] = 0x34
            it[2] = 1
            it[5] = 1
        } + question
    }

    private object AllowSocketProtection : DnsSocketProtector {
        override fun protect(socket: DatagramSocket) = true
        override fun protect(socket: java.net.Socket) = true
    }
}
