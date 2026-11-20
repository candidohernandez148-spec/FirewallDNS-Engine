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
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidUdpFlowManagerTest {

    @Test
    fun sendsAndReceivesDatagramsBidirectionallyOverLoopback() {
        DatagramSocket(0, InetAddress.getLoopbackAddress()).use { peer ->
            peer.soTimeout = 2_000
            val receivedByFlow = CountDownLatch(1)
            val response = AtomicReference<ByteArray>()
            val listener = object : AndroidUdpFlowListener {
                override fun onDatagram(datagram: ByteArray) {
                    response.set(datagram)
                    receivedByFlow.countDown()
                }
            }
            val manager = newManager(maxFlows = 1)
            try {
                val flow = manager.open(
                    InetSocketAddress(InetAddress.getLoopbackAddress(), peer.localPort),
                    listener,
                )
                val outbound = "firewalldns-outbound".toByteArray()
                assertTrue(flow.send(outbound))

                val incoming = DatagramPacket(ByteArray(128), 128)
                peer.receive(incoming)
                assertArrayEquals(outbound, incoming.data.copyOfRange(0, incoming.length))

                val reply = "firewalldns-inbound".toByteArray()
                peer.send(DatagramPacket(reply, reply.size, incoming.address, incoming.port))
                assertTrue("Flow did not deliver the peer datagram", receivedByFlow.await(2, TimeUnit.SECONDS))
                assertArrayEquals(reply, response.get())
                assertEquals(1L, manager.sentDatagramCount)
                assertEquals(1L, manager.receivedDatagramCount)
                flow.close()
            } finally {
                manager.close()
            }
            assertEquals(0, manager.activeFlowCount)
        }
    }

    @Test
    fun expiresIdleFlowsAndReleasesTheirCapacity() {
        DatagramSocket(0, InetAddress.getLoopbackAddress()).use { peer ->
            val idle = CountDownLatch(1)
            val manager = newManager(maxFlows = 1, idleTimeoutMillis = 100)
            try {
                manager.open(
                    InetSocketAddress(InetAddress.getLoopbackAddress(), peer.localPort),
                    object : AndroidUdpFlowListener {
                        override fun onDatagram(datagram: ByteArray) = Unit
                        override fun onIdleTimeout() { idle.countDown() }
                    },
                )
                assertTrue("Idle flow was not notified", idle.await(2, TimeUnit.SECONDS))
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
                while (manager.activeFlowCount != 0 && System.nanoTime() < deadline) {
                    Thread.sleep(10)
                }
                assertEquals(0, manager.activeFlowCount)
                manager.open(
                    InetSocketAddress(InetAddress.getLoopbackAddress(), peer.localPort),
                    object : AndroidUdpFlowListener {
                        override fun onDatagram(datagram: ByteArray) = Unit
                    },
                ).close()
            } finally {
                manager.close()
            }
        }
    }

    @Test
    fun enforcesFlowLimitAndReleasesCapacityWhenFlowCloses() {
        DatagramSocket(0, InetAddress.getLoopbackAddress()).use { firstPeer ->
            DatagramSocket(0, InetAddress.getLoopbackAddress()).use { secondPeer ->
                val manager = newManager(maxFlows = 1)
                try {
                    val listener = object : AndroidUdpFlowListener {
                        override fun onDatagram(datagram: ByteArray) = Unit
                    }
                    val first = manager.open(
                        InetSocketAddress(InetAddress.getLoopbackAddress(), firstPeer.localPort),
                        listener,
                    )
                    assertThrows(IllegalStateException::class.java) {
                        manager.open(
                            InetSocketAddress(InetAddress.getLoopbackAddress(), secondPeer.localPort),
                            listener,
                        )
                    }
                    first.close()
                    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2)
                    while (manager.activeFlowCount != 0 && System.nanoTime() < deadline) {
                        Thread.sleep(10)
                    }
                    assertEquals(0, manager.activeFlowCount)
                    manager.open(
                        InetSocketAddress(InetAddress.getLoopbackAddress(), secondPeer.localPort),
                        listener,
                    ).close()
                } finally {
                    manager.close()
                }
            }
        }
    }

    @Test
    fun rejectsEmptyAndOversizedDatagramsAndStopsOnClose() {
        DatagramSocket(0, InetAddress.getLoopbackAddress()).use { peer ->
            val manager = newManager(maxFlows = 1, maxDatagramBytes = 32)
            try {
                val flow = manager.open(
                    InetSocketAddress(InetAddress.getLoopbackAddress(), peer.localPort),
                    object : AndroidUdpFlowListener {
                        override fun onDatagram(datagram: ByteArray) = Unit
                    },
                )
                assertFalse(flow.send(byteArrayOf()))
                assertFalse(flow.send(ByteArray(33)))
                assertEquals(2L, manager.rejectedDatagramCount)
                flow.close()
                assertFalse(flow.send(byteArrayOf(1)))
                assertEquals(3L, manager.rejectedDatagramCount)
            } finally {
                manager.close()
            }
            assertEquals(0, manager.activeFlowCount)
        }
    }

    @Test
    fun rejectsOversizedInboundDatagramsInsteadOfDeliveringTruncatedPayloads() {
        DatagramSocket(0, InetAddress.getLoopbackAddress()).use { peer ->
            peer.soTimeout = 2_000
            val receivedByFlow = CountDownLatch(1)
            val delivered = AtomicReference<ByteArray>()
            val manager = newManager(maxFlows = 1, maxDatagramBytes = 32)
            try {
                val flow = manager.open(
                    InetSocketAddress(InetAddress.getLoopbackAddress(), peer.localPort),
                    object : AndroidUdpFlowListener {
                        override fun onDatagram(datagram: ByteArray) {
                            delivered.set(datagram)
                            receivedByFlow.countDown()
                        }
                    },
                )
                val probe = "firewalldns-probe".toByteArray()
                assertTrue(flow.send(probe))
                val source = DatagramPacket(ByteArray(128), 128)
                peer.receive(source)

                val oversized = ByteArray(33) { 7 }
                peer.send(DatagramPacket(oversized, oversized.size, source.address, source.port))
                val valid = byteArrayOf(1, 2, 3)
                peer.send(DatagramPacket(valid, valid.size, source.address, source.port))

                assertTrue(
                    "Flow did not deliver the valid datagram after rejecting the oversized one",
                    receivedByFlow.await(2, TimeUnit.SECONDS),
                )
                assertArrayEquals(valid, delivered.get())
                assertEquals(1L, manager.rejectedDatagramCount)
                assertEquals(1L, manager.receivedDatagramCount)
                flow.close()
            } finally {
                manager.close()
            }
        }
    }

    @Test
    fun rejectsQueueConfigurationThatExceedsAggregateMemoryBudget() {
        val protector = object : DnsSocketProtector {
            override fun protect(socket: DatagramSocket): Boolean = true
            override fun protect(socket: Socket): Boolean = true
        }
        assertThrows(IllegalArgumentException::class.java) {
            AndroidUdpFlowManager(
                socketFactory = AndroidProtectedUdpSocketFactory(protector),
                maxFlows = 128,
                maxQueuedDatagramsPerFlow = 256,
                maxDatagramBytes = 65_507,
            )
        }
    }

    private fun newManager(
        maxFlows: Int,
        maxDatagramBytes: Int = 1_024,
        idleTimeoutMillis: Int = 10_000,
    ): AndroidUdpFlowManager {
        val protector = object : DnsSocketProtector {
            override fun protect(socket: DatagramSocket): Boolean = true
            override fun protect(socket: Socket): Boolean = true
        }
        return AndroidUdpFlowManager(
            socketFactory = AndroidProtectedUdpSocketFactory(protector),
            maxFlows = maxFlows,
            maxQueuedDatagramsPerFlow = 4,
            maxDatagramBytes = maxDatagramBytes,
            receivePollTimeoutMillis = 25,
            idleTimeoutMillis = idleTimeoutMillis,
        )
    }
}
