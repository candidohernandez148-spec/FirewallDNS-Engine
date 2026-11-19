package com.firewalldns.engine.dns

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
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
                    healthyResolver.send(DatagramPacket(response, response.size, incoming.socketAddress))
                }
                val first = client(silentResolver.localPort, 80)
                val second = client(healthyResolver.localPort, 500)

                val result = DnsUpstreamFailoverClient(listOf(first, second)).exchange(query)
                responder.join(2_000)

                val success = assertIs<DnsUpstreamResult.Success>(result)
                assertEquals(DnsUpstreamTransport.UDP, success.response.transport)
                assertTrue(!responder.isAlive, "Secondary resolver did not finish")
            }
        }
    }

    @Test
    fun retriesWhenPrimaryReturnsMalformedDnsResponse() {
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { malformedResolver ->
            DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { healthyResolver ->
                val query = query()
                val malformedResponder = thread {
                    val incoming = DatagramPacket(ByteArray(512), 512)
                    malformedResolver.receive(incoming)
                    val malformed = query.copyOf().also {
                        it[2] = 0x81.toByte()
                        it[3] = 0x80.toByte()
                        it[7] = 1 // Advertise one answer but omit its record bytes.
                    }
                    malformedResolver.send(
                        DatagramPacket(malformed, malformed.size, incoming.socketAddress),
                    )
                }
                val healthyResponder = thread {
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

                val result = DnsUpstreamFailoverClient(
                    listOf(client(malformedResolver.localPort, 500), client(healthyResolver.localPort, 500)),
                ).exchange(query)

                malformedResponder.join(2_000)
                healthyResponder.join(2_000)
                assertIs<DnsUpstreamResult.Success>(result)
                assertTrue(!malformedResponder.isAlive, "Primary malformed responder did not finish")
                assertTrue(!healthyResponder.isAlive, "Secondary healthy responder did not finish")
            }
        }
    }

    @Test
    fun returnsLastResolverFailureWhenAllResolversFail() {
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { first ->
            DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { second ->
                val result = DnsUpstreamFailoverClient(
                    listOf(client(first.localPort, 60), client(second.localPort, 90)),
                ).exchange(query())
                assertEquals(
                    "dns_upstream_udp_timeout",
                    assertIs<DnsUpstreamResult.Failure>(result).reason,
                )
            }
        }
    }

    @Test
    fun stopsAfterConfiguredMaximumAttempts() {
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { first ->
            DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { second ->
                DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { unused ->
                    val result = DnsUpstreamFailoverClient(
                        listOf(
                            client(first.localPort, 50),
                            client(second.localPort, 50),
                            client(unused.localPort, 50),
                        ),
                        maxAttempts = 2,
                    ).exchange(query())
                    assertEquals(
                        "dns_upstream_udp_timeout",
                        assertIs<DnsUpstreamResult.Failure>(result).reason,
                    )
                }
            }
        }
    }

    @Test
    fun doesNotRetryInvalidQuery() {
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { first ->
            DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { second ->
                val result = DnsUpstreamFailoverClient(
                    listOf(client(first.localPort, 50), client(second.localPort, 50)),
                ).exchange(byteArrayOf(1, 2, 3))
                assertEquals(
                    "dns_header_truncated",
                    assertIs<DnsUpstreamResult.Failure>(result).reason,
                )
            }
        }
    }

    @Test
    fun doesNotRetryWhenSocketProtectionFails() {
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { first ->
            DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { second ->
                val secondReceived = CountDownLatch(1)
                val responder = thread {
                    runCatching {
                        second.soTimeout = 150
                        second.receive(DatagramPacket(ByteArray(512), 512))
                        secondReceived.countDown()
                    }
                }
                val refusesProtection = object : DnsSocketProtector {
                    override fun protect(socket: DatagramSocket) = false
                    override fun protect(socket: java.net.Socket) = false
                }
                val result = DnsUpstreamFailoverClient(
                    listOf(
                        DnsUpstreamClient(DnsUpstreamConfig("127.0.0.1", first.localPort), refusesProtection),
                        client(second.localPort, 100),
                    ),
                ).exchange(query())
                responder.join(1_000)
                assertEquals(
                    "dns_upstream_udp_socket_protection_failed",
                    assertIs<DnsUpstreamResult.Failure>(result).reason,
                )
                assertTrue(!secondReceived.await(20, TimeUnit.MILLISECONDS), "Failover sent an unprotected secondary query")
            }
        }
    }

    @Test
    fun cancellationIsTerminalAndDoesNotTryAnotherResolver() {
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { first ->
            DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { second ->
                val cancellation = DnsExchangeCancellation().also { it.cancel() }
                val result = DnsUpstreamFailoverClient(
                    listOf(client(first.localPort, 50), client(second.localPort, 50)),
                ).exchange(query(), cancellation)
                assertEquals(DnsUpstreamResult.Cancelled, result)
            }
        }
    }

    @Test
    fun rejectsEmptyResolverListAndInvalidAttemptCount() {
        assertFailsWith<IllegalArgumentException> { DnsUpstreamFailoverClient(emptyList()) }
        val only = listOf(client(53, 50))
        assertFailsWith<IllegalArgumentException> { DnsUpstreamFailoverClient(only, 0) }
        assertFailsWith<IllegalArgumentException> { DnsUpstreamFailoverClient(only, 2) }
    }

    private fun client(port: Int, timeout: Int) = DnsUpstreamClient(
        DnsUpstreamConfig("127.0.0.1", port, timeoutMillis = timeout),
        TestProtector,
    )

    private object TestProtector : DnsSocketProtector {
        override fun protect(socket: DatagramSocket) = true
        override fun protect(socket: java.net.Socket) = true
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
