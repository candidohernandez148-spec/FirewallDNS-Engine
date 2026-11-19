package com.firewalldns.engine.android

import android.net.VpnService
import com.firewalldns.engine.dns.DnsUpstreamConfig
import com.firewalldns.engine.dns.DnsUpstreamResult
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import kotlin.concurrent.thread
import org.junit.Assert.assertTrue
import org.junit.Test
import org.mockito.Mockito

class AndroidEngineRuntimeTest {
    @Test
    fun failoverClientProtectsUpstreamSocketThroughActiveVpnService() {
        val vpnService = Mockito.mock(VpnService::class.java)
        Mockito.`when`(vpnService.protect(Mockito.any(DatagramSocket::class.java))).thenReturn(true)

        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { server ->
            server.soTimeout = 3_000
            val responder = thread(name = "android-engine-runtime-test-dns") {
                val incoming = DatagramPacket(ByteArray(512), 512)
                server.receive(incoming)
                val query = incoming.data.copyOf(incoming.length)
                val response = query.copyOf(query.size + 16)
                response[2] = 0x81.toByte()
                response[3] = 0x80.toByte()
                response[7] = 1
                val offset = query.size
                response[offset] = 0xc0.toByte()
                response[offset + 1] = 0x0c
                response[offset + 3] = 1
                response[offset + 5] = 1
                response[offset + 9] = 60
                response[offset + 11] = 4
                response[offset + 12] = 192.toByte()
                response[offset + 13] = 0
                response[offset + 14] = 2
                response[offset + 15] = 1
                server.send(DatagramPacket(response, response.size, incoming.socketAddress))
            }

            val host = AndroidEngineRuntime(vpnService)
            val client = host.createDnsFailover(
                listOf(DnsUpstreamConfig("127.0.0.1", server.localPort, timeoutMillis = 2_000))
            )
            val result = client.exchange(query("engine-runtime.example"))
            responder.join(3_000)

            assertTrue("Expected a validated upstream response, got $result", result is DnsUpstreamResult.Success)
            Mockito.verify(vpnService).protect(Mockito.any(DatagramSocket::class.java))
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejectsEmptyUpstreamConfiguration() {
        AndroidEngineRuntime(Mockito.mock(VpnService::class.java)).createDnsFailover(emptyList())
    }

    private fun query(domain: String): ByteArray {
        val labels = domain.split('.').flatMap { label ->
            listOf(label.length.toByte()) + label.toByteArray().toList()
        } + 0.toByte()
        val question = labels.toByteArray() + byteArrayOf(0, 1, 0, 1)
        return ByteArray(12 + question.size).also {
            it[0] = 0x12
            it[1] = 0x34
            it[2] = 1
            it[5] = 1
            question.copyInto(it, 12)
        }
    }
}