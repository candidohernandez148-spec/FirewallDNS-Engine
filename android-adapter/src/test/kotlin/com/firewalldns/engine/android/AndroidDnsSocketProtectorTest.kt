package com.firewalldns.engine.android

import android.net.VpnService
import java.net.DatagramSocket
import java.net.Socket
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import org.mockito.Mockito

class AndroidDnsSocketProtectorTest {

    @Test
    fun delegatesDatagramSocketProtectionResult() {
        val vpnService = Mockito.mock(VpnService::class.java)
        val socket = Mockito.mock(DatagramSocket::class.java)
        Mockito.`when`(vpnService.protect(socket)).thenReturn(true)

        assertTrue(AndroidDnsSocketProtector(vpnService).protect(socket))
        Mockito.verify(vpnService).protect(socket)
    }

    @Test
    fun propagatesDatagramSocketProtectionFailure() {
        val vpnService = Mockito.mock(VpnService::class.java)
        val socket = Mockito.mock(DatagramSocket::class.java)
        Mockito.`when`(vpnService.protect(socket)).thenReturn(false)

        assertFalse(AndroidDnsSocketProtector(vpnService).protect(socket))
        Mockito.verify(vpnService).protect(socket)
    }

    @Test
    fun delegatesStreamSocketProtectionResult() {
        val vpnService = Mockito.mock(VpnService::class.java)
        val socket = Mockito.mock(Socket::class.java)
        Mockito.`when`(vpnService.protect(socket)).thenReturn(true)

        assertTrue(AndroidDnsSocketProtector(vpnService).protect(socket))
        Mockito.verify(vpnService).protect(socket)
    }

    @Test
    fun propagatesStreamSocketProtectionFailure() {
        val vpnService = Mockito.mock(VpnService::class.java)
        val socket = Mockito.mock(Socket::class.java)
        Mockito.`when`(vpnService.protect(socket)).thenReturn(false)

        assertFalse(AndroidDnsSocketProtector(vpnService).protect(socket))
        Mockito.verify(vpnService).protect(socket)
    }
}
