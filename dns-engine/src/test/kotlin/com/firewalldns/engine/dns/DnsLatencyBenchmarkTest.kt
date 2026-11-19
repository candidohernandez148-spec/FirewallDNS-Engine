package com.firewalldns.engine.dns

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread
import kotlin.math.ceil
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

/**
 * Opt-in loopback benchmark. It measures client-side end-to-end exchange latency,
 * not public-network or Android/VpnService latency. Enable with
 * FIREWALLDNS_RUN_DNS_BENCHMARKS=true.
 */
class DnsLatencyBenchmarkTest {
    @Test
    fun percentileCalculationUsesNearestRank() {
        val stats = LatencyPercentiles.of(listOf(1L, 2L, 3L, 4L, 100L))
        assertEquals(3L, stats.p50Nanos)
        assertEquals(4L, stats.p95Nanos)
        assertEquals(100L, stats.p99Nanos)
    }

    @Test
    fun reportsUncachedUpstreamAndResponseCacheLatencyPercentiles() {
        assumeTrue(
            System.getenv("FIREWALLDNS_RUN_DNS_BENCHMARKS") == "true",
            "Set FIREWALLDNS_RUN_DNS_BENCHMARKS=true to run the opt-in benchmark",
        )

        val warmup = 50
        val sampleCount = 500
        val allRequests = warmup + sampleCount
        DatagramSocket(0, InetAddress.getByName("127.0.0.1")).use { server ->
            server.soTimeout = 5_000
            val responderFailure = AtomicReference<Throwable?>()
            val responder = thread(name = "dns-benchmark-loopback-responder") {
                try {
                    repeat(allRequests) {
                        val incoming = DatagramPacket(ByteArray(512), 512)
                        server.receive(incoming)
                        val request = incoming.data.copyOf(incoming.length)
                        val response = positiveResponse(request)
                        server.send(DatagramPacket(response, response.size, incoming.socketAddress))
                    }
                } catch (failure: Throwable) {
                    responderFailure.set(failure)
                }
            }

            val client = DnsUpstreamClient(
                DnsUpstreamConfig("127.0.0.1", server.localPort, timeoutMillis = 5_000),
                BenchmarkSocketProtector,
            )
            repeat(warmup) { index ->
                val query = query("warm$index.bench.example", index)
                val result = assertIs<DnsUpstreamResult.Success>(client.exchange(query))
                assertEquals(DnsUpstreamTransport.UDP, result.response.transport)
            }

            val upstreamSamples = ArrayList<Long>(sampleCount)
            repeat(sampleCount) { index ->
                // A distinct QNAME guarantees a cache miss without clearing or
                // mutating the cache during the timed section.
                val query = query("sample$index.bench.example", index + warmup)
                val start = System.nanoTime()
                val result = assertIs<DnsUpstreamResult.Success>(client.exchange(query))
                upstreamSamples += System.nanoTime() - start
                assertEquals(DnsUpstreamTransport.UDP, result.response.transport)
            }
            responder.join(10_000)
            assertTrue(!responder.isAlive, "Loopback responder did not finish")
            responderFailure.get()?.let { throw AssertionError("Loopback responder failed", it) }

            val upstreamStats = LatencyPercentiles.of(upstreamSamples)
            println("DNS_BENCHMARK scenario=uncached_loopback_udp samples=$sampleCount warmup=$warmup unit=us p50=${upstreamStats.p50Micros} p95=${upstreamStats.p95Micros} p99=${upstreamStats.p99Micros}")

            val cacheQuery = query("cache.bench.example", 0x1234)
            // Prime once outside the timed cache-hit section.
            val prime = assertIs<DnsUpstreamResult.Success>(client.exchange(cacheQuery))
            assertEquals(DnsUpstreamTransport.UDP, prime.response.transport)
            val cacheSamples = ArrayList<Long>(sampleCount)
            repeat(sampleCount) { index ->
                val request = query("cache.bench.example", (index + 1) and 0xffff)
                val start = System.nanoTime()
                val result = assertIs<DnsUpstreamResult.Success>(client.exchange(request))
                cacheSamples += System.nanoTime() - start
                assertEquals(DnsUpstreamTransport.CACHE, result.response.transport)
            }
            val cacheStats = LatencyPercentiles.of(cacheSamples)
            println("DNS_BENCHMARK scenario=response_cache_hit samples=$sampleCount warmup=1 unit=us p50=${cacheStats.p50Micros} p95=${cacheStats.p95Micros} p99=${cacheStats.p99Micros}")
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

    private data class LatencyPercentiles(
        val p50Nanos: Long,
        val p95Nanos: Long,
        val p99Nanos: Long,
    ) {
        val p50Micros: Long get() = p50Nanos / 1_000
        val p95Micros: Long get() = p95Nanos / 1_000
        val p99Micros: Long get() = p99Nanos / 1_000

        companion object {
            fun of(values: List<Long>): LatencyPercentiles {
                require(values.isNotEmpty()) { "At least one latency sample is required" }
                require(values.all { it >= 0L }) { "Latency samples must not be negative" }
                val sorted = values.sorted()
                fun nearestRank(percentile: Double): Long {
                    val index = (ceil(percentile * sorted.size).toInt() - 1).coerceIn(0, sorted.lastIndex)
                    return sorted[index]
                }
                return LatencyPercentiles(
                    p50Nanos = nearestRank(0.50),
                    p95Nanos = nearestRank(0.95),
                    p99Nanos = nearestRank(0.99),
                )
            }
        }
    }
}
