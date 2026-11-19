package com.firewalldns.engine.android

import com.firewalldns.engine.dns.DnsSocketProtector
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class AndroidProtectedUdpSocketFactoryTest {

    @Test
    fun protectsSocketBeforeConnectingAndReturnsConnectedSocket() {
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { receiver ->
            var protectCalls = 0
            val protector = object : DnsSocketProtector {
                override fun protect(socket: DatagramSocket): Boolean {
                    protectCalls++
                    assertFalse("Socket must not be connected before protect()", socket.isConnected)
                    return true
                }

                override fun protect(socket: Socket): Boolean = error("TCP protection is not used")
            }

            AndroidProtectedUdpSocketFactory(protector).open(
                InetSocketAddress(InetAddress.getByName("127.0.0.1"), receiver.localPort),
                timeoutMillis = 1_500,
                receiveBufferBytes = 2_048,
            ).use { socket ->
                assertTrue(socket.isConnected)
                assertEquals(receiver.localPort, socket.port)
                assertEquals(1, protectCalls)
            }
        }
    }

    @Test
    fun closesSocketAndFailsClosedWhenVpnProtectionIsRejected() {
        val socketRef = AtomicReference<DatagramSocket>()
        val protector = object : DnsSocketProtector {
            override fun protect(socket: DatagramSocket): Boolean {
                socketRef.set(socket)
                return false
            }

            override fun protect(socket: Socket): Boolean = error("TCP protection is not used")
        }

        val failure = assertThrows(IOException::class.java) {
            AndroidProtectedUdpSocketFactory(
                protector,
                socketProvider = { DatagramSocket(null) },
            ).open(InetSocketAddress(InetAddress.getLoopbackAddress(), 443))
        }

        assertTrue(failure.message!!.contains("protection_failed"))
        assertTrue(socketRef.get().isClosed)
    }

    @Test
    fun rejectsUnresolvedEndpointBeforeCreatingSocket() {
        var protectCalls = 0
        val protector = object : DnsSocketProtector {
            override fun protect(socket: DatagramSocket): Boolean {
                protectCalls++
                return true
            }

            override fun protect(socket: Socket): Boolean = error("TCP protection is not used")
        }
        var socketCreated = false
        val factory = AndroidProtectedUdpSocketFactory(protector) {
            socketCreated = true
            DatagramSocket(null)
        }

        assertThrows(IllegalArgumentException::class.java) {
            factory.open(InetSocketAddress.createUnresolved("dns.example", 443))
        }
        assertFalse(socketCreated)
        assertEquals(0, protectCalls)
    }

    @Test
    fun rejectsInvalidSocketLimitsBeforeCreatingSocket() {
        var protectCalls = 0
        val protector = object : DnsSocketProtector {
            override fun protect(socket: DatagramSocket): Boolean {
                protectCalls++
                return true
            }

            override fun protect(socket: Socket): Boolean = error("TCP protection is not used")
        }
        var socketCreated = false
        val factory = AndroidProtectedUdpSocketFactory(protector) {
            socketCreated = true
            DatagramSocket(null)
        }

        assertThrows(IllegalArgumentException::class.java) {
            factory.open(InetSocketAddress(InetAddress.getLoopbackAddress(), 443), timeoutMillis = 0)
        }
        assertFalse(socketCreated)
        assertEquals(0, protectCalls)
    }
}
