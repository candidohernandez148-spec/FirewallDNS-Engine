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
        val p50Us: Long?,
        val p95Us: Long?,
        val p99Us: Long?,
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
                val latencies = ArrayList<Long>(samples)
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
                    val query = dnsQuery("failover$index.example.com", id)
                    val started = System.nanoTime()
                    val result = failover.exchange(query)
                    val elapsed = System.nanoTime() - started
                    if (result is DnsUpstreamResult.Success) {
                        successes++
                        latencies += elapsed
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
                val sorted = latencies.sorted()
                EndpointResult(
                    secondary = address,
                    successes = successes,
                    failures = failures,
                    p50Us = percentile(sorted, 0.50),
                    p95Us = percentile(sorted, 0.95),
                    p99Us = percentile(sorted, 0.99),
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
                  "total_latency_p50_us": ${result.p50Us ?: "null"},
                  "total_latency_p95_us": ${result.p95Us ?: "null"},
                  "total_latency_p99_us": ${result.p99Us ?: "null"},
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
                    "query_name_pattern": "failoverN.example.com"
                  },
                  "results": [
                    $resultsJson
                  ]
                }
            """.trimIndent()
            val summary = buildString {
                append("Prueba de failover del motor completada\\n")
                append("Red: $networkType; validada por Android: $validated\\n")
                append("Cada intento fuerza timeout del primario local en ${primaryTimeoutMs} ms y luego prueba el DNS público secundario.\\n")
                results.forEach {
                    append("Secundario ${it.secondary}: ${it.successes}/$samples recuperaciones correctas, ${it.failures} fallidas")
                    if (it.p50Us != null) append(" — latencia total P50 ${it.p50Us} µs, P95 ${it.p95Us} µs, P99 ${it.p99Us} µs")
                    append("\\n")
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
        "\"" + value.replace("\\\\", "\\\\\\\\").replace("\"", "\\\\"").replace("\\n", "\\n") + "\""

    private object NoopSocketProtector : DnsSocketProtector {
        override fun protect(socket: DatagramSocket): Boolean = true
        override fun protect(socket: Socket): Boolean = true
    }
}
