package com.firewalldns.engine.dns

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class DnsUpstreamCancellationTest {

    @Test
    fun cancellationClosesUdpSocketWhileWaitingForResponse() {
        val receivedQuery = CountDownLatch(1)
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { server ->
            server.soTimeout = 2_000
            val serverThread = thread {
                val packet = DatagramPacket(ByteArray(512), 512)
                server.receive(packet)
                receivedQuery.countDown()
            }
            val cancellation = DnsExchangeCancellation()
            val result = AtomicReference<DnsUpstreamResult>()
            val clientThread = thread {
                result.set(
                    DnsUpstreamClient(
                        DnsUpstreamConfig("127.0.0.1", server.localPort, timeoutMillis = 5_000),
                        TestProtector,
                    ).exchange(query(), cancellation),
                )
            }

            assertTrue(receivedQuery.await(2, TimeUnit.SECONDS), "UDP query was not sent")
            cancellation.cancel()
            clientThread.join(2_000)
            serverThread.join(2_000)

            assertTrue(!clientThread.isAlive, "UDP exchange did not stop after cancellation")
            assertEquals(DnsUpstreamResult.Cancelled, result.get())
        }
    }

    @Test
    fun cancellationClosesTcpSocketWhileWaitingForResponseAfterUdpTruncation() {
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { tcpServer ->
            tcpServer.soTimeout = 2_000
            DatagramSocket(tcpServer.localPort, InetAddress.getByName("127.0.0.1")).use { udpServer ->
                udpServer.soTimeout = 2_000
                val tcpRequestRead = CountDownLatch(1)
                val udpThread = thread {
                    val packet = DatagramPacket(ByteArray(512), 512)
                    udpServer.receive(packet)
                    val truncated = responseFor(packet.data.copyOf(packet.length)).also {
                        it[2] = 0x83.toByte()
                    }
                    udpServer.send(DatagramPacket(truncated, truncated.size, packet.socketAddress))
                }
                val tcpThread = thread {
                    tcpServer.accept().use { accepted ->
                        val input = java.io.DataInputStream(accepted.getInputStream())
                        val frameLength = input.readUnsignedShort()
                        input.readFully(ByteArray(frameLength))
                        tcpRequestRead.countDown()
                        // Wait until cancellation closes the client socket.
                        input.read()
                    }
                }
                val cancellation = DnsExchangeCancellation()
                val result = AtomicReference<DnsUpstreamResult>()
                val clientThread = thread {
                    result.set(
                        DnsUpstreamClient(
                            DnsUpstreamConfig("127.0.0.1", tcpServer.localPort, timeoutMillis = 5_000),
                            TestProtector,
                        ).exchange(query(), cancellation),
                    )
                }

                assertTrue(tcpRequestRead.await(2, TimeUnit.SECONDS), "TCP fallback did not send its query")
                cancellation.cancel()
                clientThread.join(2_000)
                udpThread.join(2_000)
                tcpThread.join(2_000)

                assertTrue(!clientThread.isAlive, "TCP exchange did not stop after cancellation")
                assertEquals(DnsUpstreamResult.Cancelled, result.get())
            }
        }
    }

    private object TestProtector : DnsSocketProtector {
        override fun protect(socket: DatagramSocket): Boolean = true
        override fun protect(socket: Socket): Boolean = true
    }

    private fun query(): ByteArray {
        val name = byteArrayOf(7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0)
        val question = name + byteArrayOf(0, 1, 0, 1)
        return ByteArray(12 + question.size).also {
            it[0] = 0x12
            it[1] = 0x34
            it[2] = 0x01
            it[5] = 1
            question.copyInto(it, 12)
        }
    }

    private fun responseFor(query: ByteArray): ByteArray = query.copyOf().also {
        it[2] = 0x81.toByte()
        it[3] = 0x80.toByte()
    }
}
