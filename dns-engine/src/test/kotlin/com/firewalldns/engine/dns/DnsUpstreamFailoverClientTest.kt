package com.firewalldns.engine.dns

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

class DnsUpstreamFailoverClientTest {
    @Test
    fun movesToNextResolverWhenFirstResolverTimesOut() {
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { silentResolver ->
            DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { healthyResolver ->
                healthyResolver.soTimeout = 2_000
                val query = query()
                val responder = thread {
                    val incoming = DatagramPacket(ByteArray(512), 512)
                    healthyResolver.receive(incoming)
                    val response = query.copyOf().also {
                        it[2] = 0x81.toByte()
                        it[3] = 0x80.toByte()
                    }
                    healthyResolver.send(
                        DatagramPacket(response, response.size, incoming.socketAddress),
                    )
                }
                val first = DnsUpstreamClient(
                    DnsUpstreamConfig("127.0.0.1", silentResolver.localPort, timeoutMillis = 80),
                    TestProtector,
                )
                val second = DnsUpstreamClient(
                    DnsUpstreamConfig("127.0.0.1", healthyResolver.localPort, timeoutMillis = 500),
                    TestProtector,
                )

                val result = DnsUpstreamFailoverClient(listOf(first, second)).exchange(query)
                responder.join(2_000)

                val success = assertIs<DnsUpstreamResult.Success>(result)
                assertEquals(DnsUpstreamTransport.UDP, success.response.transport)
                assertTrue(!responder.isAlive, "Secondary resolver did not finish")
            }
        }
    }

    @Test
    fun returnsLastResolverFailureWhenAllResolversFail() {
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { first ->
            DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { second ->
                val result = DnsUpstreamFailoverClient(
                    listOf(
                        DnsUpstreamClient(
                            DnsUpstreamConfig("127.0.0.1", first.localPort, timeoutMillis = 60),
                            TestProtector,
                        ),
                        DnsUpstreamClient(
                            DnsUpstreamConfig("127.0.0.1", second.localPort, timeoutMillis = 90),
                            TestProtector,
                        ),
                    ),
                ).exchange(query())

                assertEquals(
                    "dns_upstream_udp_timeout",
                    assertIs<DnsUpstreamResult.Failure>(result).reason,
                )
            }
        }
    }

    @Test
    fun rejectsEmptyResolverList() {
        kotlin.test.assertFailsWith<IllegalArgumentException> {
            DnsUpstreamFailoverClient(emptyList())
        }
    }

    private object TestProtector : DnsSocketProtector {
        override fun protect(socket: DatagramSocket): Boolean = true
        override fun protect(socket: java.net.Socket): Boolean = true
    }

    private fun query(): ByteArray {
        val qname = byteArrayOf(7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0)
        val question = qname + byteArrayOf(0, 1, 0, 1)
        return ByteArray(12 + question.size).also {
            it[0] = 0x34
            it[1] = 0x12
            it[2] = 0x01
            it[5] = 1
            question.copyInto(it, 12)
        }
    }
}
