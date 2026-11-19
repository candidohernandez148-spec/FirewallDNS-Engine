package com.firewalldns.engine.android

import com.firewalldns.engine.dns.DnsSocketProtector
import java.io.IOException
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicReference
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.mockito.Mockito

class AndroidProtectedUdpSocketFactoryTest {

    @Test
    fun protectsSocketBeforeConnectingAndReturnsConnectedSocket() {
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { receiver ->
            val protector = Mockito.mock(DnsSocketProtector::class.java)
            Mockito.`when`(protector.protect(Mockito.any(DatagramSocket::class.java))).thenAnswer { invocation ->
                val socket = invocation.getArgument<DatagramSocket>(0)
                assertFalse("Socket must not be connected before protect()", socket.isConnected)
                true
            }

            AndroidProtectedUdpSocketFactory(protector).open(
                InetSocketAddress(InetAddress.getByName("127.0.0.1"), receiver.localPort),
                timeoutMillis = 1_500,
                receiveBufferBytes = 2_048,
            ).use { socket ->
                assertTrue(socket.isConnected)
                assertEquals(receiver.localPort, socket.port)
                Mockito.verify(protector).protect(socket)
            }
        }
    }

    @Test
    fun closesSocketAndFailsClosedWhenVpnProtectionIsRejected() {
        val socketRef = AtomicReference<DatagramSocket>()
        val protector = Mockito.mock(DnsSocketProtector::class.java)
        Mockito.`when`(protector.protect(Mockito.any(DatagramSocket::class.java))).thenAnswer { invocation ->
            socketRef.set(invocation.getArgument(0))
            false
        }

        val failure = assertThrows(IOException::class.java) {
            AndroidProtectedUdpSocketFactory(
                protector,
                socketProvider = { DatagramSocket(null) },
            ).open(InetSocketAddress(InetAddress.getLoopbackAddress(), 443))
        }

        assertTrue(failure.message!!.contains("protection_failed"))
        assertTrue(socketRef.get().isClosed)
        Mockito.verify(protector).protect(socketRef.get())
    }

    @Test
    fun rejectsUnresolvedEndpointBeforeCreatingSocket() {
        val provider = Mockito.mock(DnsSocketProtector::class.java)
        var socketCreated = false
        val factory = AndroidProtectedUdpSocketFactory(provider) {
            socketCreated = true
            DatagramSocket(null)
        }

        assertThrows(IllegalArgumentException::class.java) {
            factory.open(InetSocketAddress.createUnresolved("dns.example", 443))
        }
        assertFalse(socketCreated)
        Mockito.verifyNoInteractions(provider)
    }

    @Test
    fun rejectsInvalidSocketLimitsBeforeCreatingSocket() {
        val protector = Mockito.mock(DnsSocketProtector::class.java)
        var socketCreated = false
        val factory = AndroidProtectedUdpSocketFactory(protector) {
            socketCreated = true
            DatagramSocket(null)
        }

        assertThrows(IllegalArgumentException::class.java) {
            factory.open(InetSocketAddress(InetAddress.getLoopbackAddress(), 443), timeoutMillis = 0)
        }
        assertFalse(socketCreated)
        Mockito.verifyNoInteractions(protector)
    }
}
