package com.firewalldns.engine.dns

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class DnsUpstreamClientTest {
    @Test fun forwardsUdpQueryAndValidatesResponse() {
        DatagramSocket(0, InetAddress.getLoopbackAddress()).use { server ->
            server.soTimeout = 2_000
            val query = query("example.com")
            val responder = thread {
                val incoming = DatagramPacket(ByteArray(512), 512)
                server.receive(incoming)
                val response = responseFor(query)
                server.send(DatagramPacket(response, response.size, incoming.socketAddress))
            }

            val result = DnsUpstreamClient(
                DnsUpstreamConfig("127.0.0.1", server.localPort, timeoutMillis = 2_000),
            ).exchange(query)

            responder.join(2_000)
            val success = assertIs<DnsUpstreamResult.Success>(result)
            assertEquals(DnsUpstreamTransport.UDP, success.response.transport)
            assertEquals(0x1234, u16(success.response.message, 0))
        }
    }

    @Test fun rejectsResponseWithDifferentTransactionId() {
        DatagramSocket(0, InetAddress.getLoopbackAddress()).use { server ->
            server.soTimeout = 2_000
            val query = query("example.com")
            val responder = thread {
                val incoming = DatagramPacket(ByteArray(512), 512)
                server.receive(incoming)
                val response = responseFor(query)
                response[0] = 0x56
                response[1] = 0x78
                server.send(DatagramPacket(response, response.size, incoming.socketAddress))
            }

            val result = DnsUpstreamClient(
                DnsUpstreamConfig("127.0.0.1", server.localPort, timeoutMillis = 2_000),
            ).exchange(query)

            responder.join(2_000)
            assertEquals(
                "dns_upstream_transaction_id_mismatch",
                assertIs<DnsUpstreamResult.Failure>(result).reason,
            )
        }
    }

    @Test fun refusesUnprotectedSocketBeforeSending() {
        DatagramSocket(0, InetAddress.getLoopbackAddress()).use { server ->
            val query = query("example.com")
            val protector = object : DnsSocketProtector {
                override fun protect(socket: DatagramSocket): Boolean = false
            }
            val result = DnsUpstreamClient(
                DnsUpstreamConfig("127.0.0.1", server.localPort),
                protector,
            ).exchange(query)
            assertEquals(
                "dns_upstream_udp_socket_protection_failed",
                assertIs<DnsUpstreamResult.Failure>(result).reason,
            )
        }
    }

    @Test fun rejectsMalformedQueryBeforeOpeningSocket() {
        val result = DnsUpstreamClient(DnsUpstreamConfig("127.0.0.1")).exchange(byteArrayOf(1, 2, 3))
        assertEquals("dns_header_truncated", assertIs<DnsUpstreamResult.Failure>(result).reason)
    }

    private fun query(domain: String): ByteArray {
        val name = domain.split('.').flatMap { label ->
            listOf(label.length.toByte()) + label.toByteArray(Charsets.US_ASCII).toList()
        } + 0.toByte()
        val question = name.toByteArray() + byteArrayOf(0, 1, 0, 1)
        return ByteArray(12 + question.size).also {
            it[0] = 0x12
            it[1] = 0x34
            it[2] = 0x01
            it[5] = 1
            question.copyInto(it, 12)
        }
    }

    private fun responseFor(query: ByteArray): ByteArray =
        query.copyOf().also {
            it[2] = 0x81.toByte() // QR + RD
            it[3] = 0x80.toByte() // RA
        }

    private fun u16(bytes: ByteArray, offset: Int) =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)
}
