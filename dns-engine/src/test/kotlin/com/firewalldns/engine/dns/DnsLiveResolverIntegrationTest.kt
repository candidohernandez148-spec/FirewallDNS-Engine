package com.firewalldns.engine.dns

import java.net.DatagramSocket
import java.net.Socket
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.assertIs
import org.junit.jupiter.api.Assumptions.assumeTrue

/**
 * Opt-in integration tests against public recursive resolvers.
 * Enable only where outbound DNS (UDP/TCP 53) is permitted.
 */
class DnsLiveResolverIntegrationTest {
    @Test
    fun cloudflareResolverAnswersRealDnsQuery() = verifyResolver("1.1.1.1")

    @Test
    fun googleResolverAnswersRealDnsQuery() = verifyResolver("8.8.8.8")

    @Test
    fun quad9ResolverAnswersRealDnsQuery() = verifyResolver("9.9.9.9")

    private fun verifyResolver(address: String) {
        assumeTrue(
            System.getenv("FIREWALLDNS_RUN_LIVE_DNS_TESTS") == "true",
            "Set FIREWALLDNS_RUN_LIVE_DNS_TESTS=true to enable external resolver tests",
        )
        val result = DnsUpstreamClient(
            config = DnsUpstreamConfig(
                host = address,
                port = 53,
                timeoutMillis = 4_000,
                udpBufferBytes = 4_096,
            ),
            socketProtector = NoopSocketProtector,
        ).exchange(exampleComQuery())

        val success = assertIs<DnsUpstreamResult.Success>(
            result,
            "Resolver $address did not return a valid DNS response: ${result}",
        )
        val response = success.response.message
        val flags = u16(response, 2)
        assertTrue(flags and 0x8000 != 0, "Resolver $address response must have QR=1")
        assertTrue(flags and 0x000f == 0, "Resolver $address returned a DNS error RCODE")
        assertTrue(u16(response, 4) == 1, "Resolver $address response must echo one question")
        assertTrue(
            success.response.transport == DnsUpstreamTransport.UDP ||
                success.response.transport == DnsUpstreamTransport.TCP,
            "Unexpected transport ${success.response.transport}",
        )
    }

    private fun exampleComQuery(): ByteArray {
        val qname = byteArrayOf(
            7, 'e'.code.toByte(), 'x'.code.toByte(), 'a'.code.toByte(),
            'm'.code.toByte(), 'p'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            3, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(), 0,
        )
        val question = qname + byteArrayOf(0, 1, 0, 1)
        return ByteArray(12).also {
            it[0] = 0x46
            it[1] = 0x44
            it[2] = 0x01
            it[5] = 1
        } + question
    }

    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private object NoopSocketProtector : DnsSocketProtector {
        override fun protect(socket: DatagramSocket): Boolean = true
        override fun protect(socket: Socket): Boolean = true
    }
}
