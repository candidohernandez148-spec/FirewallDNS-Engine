package com.firewalldns.engine.android

import android.util.Log
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.firewalldns.engine.dns.DnsSocketProtector
import com.firewalldns.engine.dns.DnsUpstreamClient
import com.firewalldns.engine.dns.DnsUpstreamConfig
import com.firewalldns.engine.dns.DnsUpstreamResult
import com.firewalldns.engine.dns.DnsUpstreamTransport
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.math.ceil
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

/**
 * On-device Android runtime benchmark using a loopback DNS responder.
 *
 * This intentionally uses a no-op protector: it measures Android runtime,
 * socket, client and cache overhead, but NOT an active VpnService.protect(),
 * TUN traversal, Wi-Fi/mobile radio or a public resolver.
 */
@RunWith(AndroidJUnit4::class)
class AndroidDnsLatencyBenchmarkTest {
    @Test
    fun reportsAndroidRuntimeDnsLatencyPercentiles() {
        val warmup = 30
        val sampleCount = 250
        val requestCount = warmup + sampleCount

        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { server ->
            server.soTimeout = 10_000
            val responderFailure = AtomicReference<Throwable?>()
            val responder = thread(name = "firewalldns-android-benchmark-responder") {
                try {
                    repeat(requestCount) {
                        val incoming = DatagramPacket(ByteArray(512), 512)
                        server.receive(incoming)
                        val request = incoming.data.copyOf(incoming.length)
                        val response = positiveResponse(request)
                        server.send(DatagramPacket(response, response.size, incoming.socketAddress))
                    }
                } catch (failure: Throwable) {
                    if (!server.isClosed) responderFailure.set(failure)
                }
            }

            try {
                val client = DnsUpstreamClient(
                    DnsUpstreamConfig("127.0.0.1", server.localPort, timeoutMillis = 5_000),
                    BenchmarkSocketProtector,
                )

                repeat(warmup) { index ->
                    val result = client.exchange(query("warm$index.android-bench.example", index))
                    assertTrue("Warmup request failed: $result", result is DnsUpstreamResult.Success)
                }

                val upstreamSamples = ArrayList<Long>(sampleCount)
                repeat(sampleCount) { index ->
                    val request = query("sample$index.android-bench.example", index + warmup)
                    val started = System.nanoTime()
                    val result = client.exchange(request)
                    upstreamSamples += System.nanoTime() - started
                    val success = result as? DnsUpstreamResult.Success
                    assertTrue("Upstream request failed: $result", success != null)
                    assertEquals(DnsUpstreamTransport.UDP, success!!.response.transport)
                }

                responder.join(15_000)
                assertTrue("Loopback responder did not finish", !responder.isAlive)
                responderFailure.get()?.let { throw AssertionError("Loopback responder failed", it) }

                val upstream = Percentiles.of(upstreamSamples)
                Log.i(
                    TAG,
                    "DNS_BENCHMARK scenario=android_loopback_udp samples=$sampleCount warmup=$warmup unit=us p50=${upstream.p50Micros} p95=${upstream.p95Micros} p99=${upstream.p99Micros}",
                )

                // The final unique QNAME is cached by the upstream sample. A new
                // DNS transaction ID must still be served from the response cache.
                val cacheSamples = ArrayList<Long>(sampleCount)
                repeat(sampleCount) { index ->
                    val request = query("sample${sampleCount - 1}.android-bench.example", (index + 1) and 0xffff)
                    val started = System.nanoTime()
                    val result = client.exchange(request)
                    cacheSamples += System.nanoTime() - started
                    val success = result as? DnsUpstreamResult.Success
                    assertTrue("Cache request failed: $result", success != null)
                    assertEquals(DnsUpstreamTransport.CACHE, success!!.response.transport)
                }

                val cache = Percentiles.of(cacheSamples)
                Log.i(
                    TAG,
                    "DNS_BENCHMARK scenario=android_response_cache_hit samples=$sampleCount warmup=0 unit=us p50=${cache.p50Micros} p95=${cache.p95Micros} p99=${cache.p99Micros}",
                )
            } finally {
                server.close()
                responder.join(1_000)
            }
        }
    }

    private object BenchmarkSocketProtector : DnsSocketProtector {
        override fun protect(socket: DatagramSocket): Boolean = true
        override fun protect(socket: Socket): Boolean = true
    }

    private fun query(domain: String, id: Int): ByteArray {
        val labels = domain.split('.').flatMap { label ->
            listOf(label.length.toByte()) + label.toByteArray().toList()
        } + 0.toByte()
        val question = labels.toByteArray() + byteArrayOf(0, 1, 0, 1)
        return ByteArray(12 + question.size).also {
            it[0] = (id ushr 8).toByte()
            it[1] = id.toByte()
            it[2] = 1
            it[5] = 1
            question.copyInto(it, 12)
        }
    }

    private fun positiveResponse(query: ByteArray): ByteArray {
        val response = ByteArray(query.size + 16)
        query.copyInto(response)
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
        return response
    }

    private data class Percentiles(val p50Nanos: Long, val p95Nanos: Long, val p99Nanos: Long) {
        val p50Micros: Long get() = p50Nanos / 1_000
        val p95Micros: Long get() = p95Nanos / 1_000
        val p99Micros: Long get() = p99Nanos / 1_000

        companion object {
            fun of(values: List<Long>): Percentiles {
                require(values.isNotEmpty())
                require(values.all { it >= 0L })
                val sorted = values.sorted()
                fun nearestRank(percentile: Double): Long {
                    val index = (ceil(percentile * sorted.size).toInt() - 1)
                        .coerceIn(0, sorted.lastIndex)
                    return sorted[index]
                }
                return Percentiles(nearestRank(0.50), nearestRank(0.95), nearestRank(0.99))
            }
        }
    }

    private companion object {
        const val TAG = "FirewallDNSBenchmark"
    }
}
