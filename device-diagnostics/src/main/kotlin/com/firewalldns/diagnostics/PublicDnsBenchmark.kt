package com.firewalldns.diagnostics

import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import com.firewalldns.engine.dns.DnsSocketProtector
import com.firewalldns.engine.dns.DnsUpstreamClient
import com.firewalldns.engine.dns.DnsUpstreamConfig
import com.firewalldns.engine.dns.DnsUpstreamResult
import java.net.DatagramSocket
import java.net.Socket
import java.time.Instant
import java.util.UUID
import kotlin.math.ceil

/**
 * Explicit, user-triggered public DNS test. Uses numeric resolver addresses and
 * records the currently active Android transport. It does not alter system DNS.
 */
internal object PublicDnsBenchmark {
    private data class ResolverResult(
        val address: String,
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

        // 3 warmups and 30 measured requests per resolver. A distinct DNS ID
        // prevents the engine response cache from masking upstream exchanges.
        val warmups = 3
        val samples = 30
        val resolvers = listOf("1.1.1.1", "8.8.8.8")
        val results = resolvers.mapIndexed { resolverIndex, address ->
            val client = DnsUpstreamClient(
                DnsUpstreamConfig(address, port = 53, timeoutMillis = 2_500),
                NoopSocketProtector,
            )
            val latencies = ArrayList<Long>(samples)
            val errors = linkedMapOf<String, Int>()
            var successes = 0
            var failures = 0
            repeat(warmups + samples) { index ->
                val id = (resolverIndex * 10_000 + index + 1) and 0xffff
                // A fresh, unpredictable QNAME per request avoids measuring a
                // recursive resolver's cached answer for the same example.com.
                val nonce = UUID.randomUUID().toString().replace("-", "").take(12)
                val queryName = "fdns-$resolverIndex-$index-$nonce.example.com"
                val query = dnsQuery(queryName, id)
                val started = System.nanoTime()
                val result = client.exchange(query)
                val elapsed = System.nanoTime() - started
                if (index < warmups) {
                    if (result !is DnsUpstreamResult.Success) {
                        val reason = when (result) {
                            is DnsUpstreamResult.Failure -> result.reason
                            DnsUpstreamResult.Cancelled -> "cancelled"
                            is DnsUpstreamResult.Success -> "success"
                        }
                        errors[reason] = (errors[reason] ?: 0) + 1
                    }
                } else if (result is DnsUpstreamResult.Success) {
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
            ResolverResult(
                address = address,
                successes = successes,
                failures = failures,
                p50Us = percentile(sorted, 0.50),
                p95Us = percentile(sorted, 0.95),
                p99Us = percentile(sorted, 0.99),
                errors = errors,
            )
        }

        val resolverJson = results.joinToString(",\n") { result ->
            val errorJson = result.errors.entries.joinToString(",") {
                "${json(it.key)}:${it.value}"
            }
            """
            {
              "resolver": "${result.address}",
              "transport": "udp",
              "successes": ${result.successes},
              "failures": ${result.failures},
              "p50_us": ${result.p50Us ?: "null"},
              "p95_us": ${result.p95Us ?: "null"},
              "p99_us": ${result.p99Us ?: "null"},
              "errors": {$errorJson}
            }
            """.trimIndent()
        }
        val report = """
            {
              "format": "firewalldns-public-dns-diagnostic-v1",
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
                "vpn_transport_present": ${transports.contains("vpn")},
                "user_should_repeat_after_switching_wifi_and_mobile": true
              },
              "scope": {
                "public_dns_tested": true,
                "resolver_port": 53,
                "protocol": "udp",
                "vpn_service_protect_measured": false,
                "system_dns_changed": false,
                "personal_dns_queries_collected": false
              },
              "configuration": {
                "warmup_per_resolver": $warmups,
                "samples_per_resolver": $samples,
                "query_name_pattern": "fdns-resolverIndex-sampleIndex-randomNonce.example.com",
                "unique_query_name_per_request": true,
                "timeout_ms": 2500
              },
              "resolvers": [
                $resolverJson
              ]
            }
        """.trimIndent()
        val summary = buildString {
            append("Prueba DNS público completada\n")
            append("Red detectada: $networkType; validada por Android: $validated\n")
            results.forEach {
                append("${it.address}: ${it.successes}/$samples correctas, ${it.failures} fallidas")
                if (it.p50Us != null) append(" — P50 ${it.p50Us} µs, P95 ${it.p95Us} µs, P99 ${it.p99Us} µs")
                append("\n")
            }
            append("No cambia los DNS del sistema. Repite la prueba tras cambiar manualmente entre Wi-Fi y datos móviles.")
        }
        return report to summary
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
