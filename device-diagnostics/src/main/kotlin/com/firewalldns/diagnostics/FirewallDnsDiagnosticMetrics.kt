package com.firewalldns.diagnostics

import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicLongArray

/**
 * Bounded, payload-free counters for the single FirewallDNS diagnostic report.
 * This observes only packets actually delivered by Android to this TUN session.
 */
class FirewallDnsDiagnosticMetrics {
    private val packets = AtomicLong()
    private val bytes = AtomicLong()
    private val counts = ConcurrentHashMap<String, ConcurrentHashMap<String, AtomicLong>>()
    private val latencyCursor = AtomicLong()
    private val latencySamples = AtomicLongArray(MAX_LATENCY_SAMPLES)

    fun reset() {
        packets.set(0)
        bytes.set(0)
        counts.clear()
        latencyCursor.set(0)
        for (i in 0 until MAX_LATENCY_SAMPLES) latencySamples.set(i, 0)
    }

    fun record(packet: ByteArray, length: Int) {
        val started = System.nanoTime()
        val classification = FirewallDnsTrafficClassifier.classify(
            if (length == packet.size) packet else packet.copyOf(length.coerceIn(0, packet.size)),
        )
        val elapsedMicros = ((System.nanoTime() - started) / 1_000L).coerceAtLeast(0L)
        packets.incrementAndGet()
        bytes.addAndGet(length.toLong().coerceAtLeast(0L))
        increment("network", classification.network)
        increment("transport", classification.transport)
        increment("application", classification.application)
        increment("certainty", classification.certainty.name)
        increment("reason", classification.reason)
        val slot = (latencyCursor.getAndIncrement() % MAX_LATENCY_SAMPLES).toInt()
        latencySamples.set(slot, elapsedMicros)
    }

    fun snapshotJson(): String {
        val sampleCount = latencyCursor.get().coerceAtMost(MAX_LATENCY_SAMPLES.toLong()).toInt()
        val samples = LongArray(sampleCount) { latencySamples.get(it) }.sortedArray()
        fun percentile(p: Double): Long {
            if (samples.isEmpty()) return 0L
            val index = (kotlin.math.ceil(p * samples.size).toInt() - 1).coerceIn(0, samples.lastIndex)
            return samples[index]
        }
        return """{
  "packets_classified": ${packets.get()},
  "bytes_classified": ${bytes.get()},
  "classification_latency_us": {
    "samples": $sampleCount,
    "p50": ${percentile(0.50)},
    "p95": ${percentile(0.95)},
    "p99": ${percentile(0.99)}
  },
  "by_network": ${mapJson("network")},
  "by_transport": ${mapJson("transport")},
  "by_application": ${mapJson("application")},
  "by_certainty": ${mapJson("certainty")},
  "by_reason": ${mapJson("reason")}
}""".trimIndent()
    }

    private fun increment(group: String, key: String) {
        counts.computeIfAbsent(group) { ConcurrentHashMap() }
            .computeIfAbsent(key) { AtomicLong() }
            .incrementAndGet()
    }

    private fun mapJson(group: String): String {
        val entries = counts[group]?.entries?.sortedBy { it.key }.orEmpty()
        return entries.joinToString(prefix = "{", postfix = "}") { (key, value) ->
            "\"$key\": ${value.get()}"
        }
    }

    private companion object {
        const val MAX_LATENCY_SAMPLES = 1024
    }
}
