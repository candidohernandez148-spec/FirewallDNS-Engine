package com.firewalldns.diagnostics

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import com.firewalldns.engine.dns.DnsSocketProtector
import com.firewalldns.engine.dns.DnsUpstreamClient
import com.firewalldns.engine.dns.DnsUpstreamConfig
import com.firewalldns.engine.dns.DnsUpstreamFailoverClient
import com.firewalldns.engine.dns.DnsUpstreamResult
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.time.Instant
import java.util.UUID
import kotlin.math.ceil

/**
 * Device-level failover check. A deliberately silent loopback primary produces
 * a controlled timeout; the engine must then reach a real public secondary.
 * This is direct UDP/53 diagnostic traffic, not an active VPN/TUN test.
 */
internal object FailoverDnsBenchmark {
    private data class EndpointResult(
        val secondary: String,
        val successes: Int,
        val failures: Int,
        val totalP50Us: Long?,
        val totalP95Us: Long?,
        val totalP99Us: Long?,
        val primaryP50Us: Long?,
        val primaryP95Us: Long?,
        val secondaryP50Us: Long?,
        val secondaryP95Us: Long?,
        val errors: Map<String, Int>,
    )

    fun execute(context: Context): Pair<String, String> {
        val connectivity = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val network = connectivity.activeNetwork
        val capabilities = network?.let(connectivity::getNetworkCapabilities)
        val transports = buildList {
            if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true) add("wifi")
            if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true) add("cellular")
            if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true) add("ethernet")
            if (capabilities?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true) add("vpn")
        }
        val networkType = transports.joinToString("+").ifBlank { "unknown_or_disconnected" }
        val validated = capabilities?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) == true
        val samples = 10
        val primaryTimeoutMs = 350
        val secondaryTimeoutMs = 1_500
        val secondaryResolvers = listOf("1.1.1.1", "8.8.8.8")

        DatagramSocket(null).use { silentPrimary ->
            silentPrimary.bind(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0))
            val results = secondaryResolvers.mapIndexed { resolverIndex, address ->
                val secondary = DnsUpstreamClient(
                    DnsUpstreamConfig(address, port = 53, timeoutMillis = secondaryTimeoutMs),
                    NoopSocketProtector,
                )
                val totalLatencies = ArrayList<Long>(samples)
                val primaryLatencies = ArrayList<Long>(samples)
                val secondaryLatencies = ArrayList<Long>(samples)
                val errors = linkedMapOf<String, Int>()
                var successes = 0
                var failures = 0
                repeat(samples) { index ->
                    // The silent local primary is intentionally never read/responded to.
                    // Unique IDs/QNAMEs prevent the engine response cache from hiding attempts.
                    val primary = DnsUpstreamClient(
                        DnsUpstreamConfig("127.0.0.1", silentPrimary.localPort, timeoutMillis = primaryTimeoutMs),
                        NoopSocketProtector,
                    )
                    val failover = DnsUpstreamFailoverClient(listOf(primary, secondary), maxAttempts = 2)
                    val id = (resolverIndex * 20_000 + index + 1) and 0xffff
                    val nonce = UUID.randomUUID().toString().replace("-", "").take(12)
                    val query = dnsQuery("fdns-failover-$resolverIndex-$index-$nonce.example.com", id)
                    val started = System.nanoTime()
                    val attemptDurations = mutableMapOf<Int, Long>()
                    val result = failover.exchange(query, com.firewalldns.engine.dns.DnsExchangeCancellation()) {
                        attemptDurations[it.resolverIndex] = it.elapsedNanos
                    }
                    val elapsed = System.nanoTime() - started
                    attemptDurations[0]?.let { primaryLatencies += it }
                    attemptDurations[1]?.let { secondaryLatencies += it }
                    if (result is DnsUpstreamResult.Success) {
                        successes++
                        totalLatencies += elapsed
                    } else {
                        failures++
                        val reason = when (result) {
                            is DnsUpstreamResult.Failure -> result.reason
                            DnsUpstreamResult.Cancelled -> "cancelled"
                            is DnsUpstreamResult.Success -> "success"
                        }
                        errors[reason] = (errors[reason] ?: 0) + 1
                    }
                }
                EndpointResult(
                    secondary = address,
                    successes = successes,
                    failures = failures,
                    totalP50Us = percentile(totalLatencies.sorted(), 0.50),
                    totalP95Us = percentile(totalLatencies.sorted(), 0.95),
                    totalP99Us = percentile(totalLatencies.sorted(), 0.99),
                    primaryP50Us = percentile(primaryLatencies.sorted(), 0.50),
                    primaryP95Us = percentile(primaryLatencies.sorted(), 0.95),
                    secondaryP50Us = percentile(secondaryLatencies.sorted(), 0.50),
                    secondaryP95Us = percentile(secondaryLatencies.sorted(), 0.95),
                    errors = errors,
                )
            }

            val resultsJson = results.joinToString(",\n") { result ->
                val errorJson = result.errors.entries.joinToString(",") { "${json(it.key)}:${it.value}" }
                """
                {
                  "simulated_primary": "127.0.0.1 (silent; controlled timeout)",
                  "secondary": "${result.secondary}",
                  "attempts": $samples,
                  "secondary_successes": ${result.successes},
                  "failures": ${result.failures},
                  "primary_attempt_p50_us": ${result.primaryP50Us ?: "null"},
                  "primary_attempt_p95_us": ${result.primaryP95Us ?: "null"},
                  "secondary_attempt_p50_us": ${result.secondaryP50Us ?: "null"},
                  "secondary_attempt_p95_us": ${result.secondaryP95Us ?: "null"},
                  "total_latency_p50_us": ${result.totalP50Us ?: "null"},
                  "total_latency_p95_us": ${result.totalP95Us ?: "null"},
                  "total_latency_p99_us": ${result.totalP99Us ?: "null"},
                  "errors": {$errorJson}
                }
                """.trimIndent()
            }
            val report = """
                {
                  "format": "firewalldns-engine-failover-diagnostic-v1",
                  "created_at_utc": "${Instant.now()}",
                  "device": {
                    "manufacturer": ${json(Build.MANUFACTURER)},
                    "model": ${json(Build.MODEL)},
                    "android_release": ${json(Build.VERSION.RELEASE)},
                    "sdk_int": ${Build.VERSION.SDK_INT}
                  },
                  "network": {
                    "active_transport": ${json(networkType)},
                    "validated_by_android": $validated,
                    "vpn_transport_present": ${transports.contains("vpn")}
                  },
                  "scope": {
                    "engine_failover_exercised": true,
                    "primary_failure_simulated_locally": true,
                    "secondary_public_dns_tested": true,
                    "protocol": "udp",
                    "resolver_port": 53,
                    "vpn_service_protect_measured": false,
                    "tun_traversal_measured": false,
                    "system_dns_changed": false,
                    "personal_dns_queries_collected": false
                  },
                  "configuration": {
                    "samples_per_secondary": $samples,
                    "primary_timeout_ms": $primaryTimeoutMs,
                    "secondary_timeout_ms": $secondaryTimeoutMs,
                    "query_name_pattern": "fdns-failover-resolverIndex-sampleIndex-randomNonce.example.com",
                    "unique_query_name_per_request": true
                  },
                  "results": [
                    $resultsJson
                  ]
                }
            """.trimIndent()
            val summary = buildString {
                append("Prueba de failover del motor completada\n")
                append("Red: $networkType; validada por Android: $validated\n")
                append("Cada intento fuerza timeout del primario local en ${primaryTimeoutMs} ms y luego prueba el DNS público secundario.\n")
                results.forEach {
                    append("Secundario ${it.secondary}: ${it.successes}/$samples recuperaciones correctas, ${it.failures} fallidas")
                    if (it.totalP50Us != null) append(" — primario P50 ${it.primaryP50Us} µs; secundario P50 ${it.secondaryP50Us} µs; total P50 ${it.totalP50Us} µs, P95 ${it.totalP95Us} µs, P99 ${it.totalP99Us} µs")
                    append("\n")
                }
                append("Alcance: valida failover real del motor hacia UDP/53, pero no VPN activa, TUN ni VpnService.protect().")
            }
            return report to summary
        }
    }

    private fun percentile(sorted: List<Long>, p: Double): Long? {
        if (sorted.isEmpty()) return null
        val index = (ceil(p * sorted.size).toInt() - 1).coerceIn(0, sorted.lastIndex)
        return sorted[index] / 1_000
    }

    private fun dnsQuery(domain: String, id: Int): ByteArray {
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
    private fun json(value: String): String =
        "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\""

    private object NoopSocketProtector : DnsSocketProtector {
        override fun protect(socket: DatagramSocket): Boolean = true
        override fun protect(socket: Socket): Boolean = true
    }
}
