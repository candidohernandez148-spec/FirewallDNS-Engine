package com.firewalldns.diagnostics

import android.app.Activity
import android.content.Intent
import android.os.Build
import android.os.Bundle
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import com.firewalldns.engine.dns.DnsSocketProtector
import com.firewalldns.engine.dns.DnsUpstreamClient
import com.firewalldns.engine.dns.DnsUpstreamConfig
import com.firewalldns.engine.dns.DnsUpstreamResult
import com.firewalldns.engine.dns.DnsUpstreamTransport
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import java.time.Instant
import kotlin.concurrent.thread

/**
 * Local-only diagnostic. It deliberately does not claim to measure an active
 * VpnService, VpnService.protect(), TUN traversal, Wi-Fi/mobile radio or public DNS.
 */
class MainActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var runButton: Button
    private lateinit var exportButton: Button
    private var reportJson: String? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "FirewallDNS - Diagnóstico"
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 32, 32, 32)
        }
        val heading = TextView(this).apply {
            text = "Diagnóstico del motor DNS"
            textSize = 23f
        }
        val explanation = TextView(this).apply {
            text = "Ejecuta pruebas locales en este celular. No modifica tu VPN ni cambia los DNS del sistema. No recopila historial ni dominios personales."
            textSize = 16f
            setPadding(0, 20, 0, 20)
        }
        status = TextView(this).apply {
            text = "Listo para probar. Se medirán 250 consultas DNS locales y 250 aciertos de caché."
            textSize = 15f
            setPadding(0, 12, 0, 24)
        }
        runButton = Button(this).apply {
            text = "Ejecutar diagnóstico"
            setOnClickListener { runDiagnostic() }
        }
        exportButton = Button(this).apply {
            text = "Guardar informe JSON"
            isEnabled = false
            setOnClickListener { exportReport() }
        }
        root.addView(heading)
        root.addView(explanation)
        root.addView(status, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        root.addView(runButton)
        root.addView(exportButton)
        val scroll = ScrollView(this).apply { addView(root) }
        setContentView(scroll)
    }

    private fun runDiagnostic() {
        runButton.isEnabled = false
        exportButton.isEnabled = false
        reportJson = null
        status.text = "Ejecutando pruebas locales… Mantén abierta esta pantalla."
        thread(name = "firewalldns-device-diagnostic") {
            try {
                val report = executeBenchmark()
                reportJson = report.first
                runOnUiThread {
                    status.text = report.second + "\n\nPuedes guardar el informe JSON y adjuntarlo en el chat."
                    exportButton.isEnabled = true
                    runButton.isEnabled = true
                }
            } catch (failure: Throwable) {
                runOnUiThread {
                    status.text = "La prueba no terminó: ${failure.javaClass.simpleName}: ${failure.message ?: "sin detalle"}"
                    runButton.isEnabled = true
                }
            }
        }
    }

    private fun executeBenchmark(): Pair<String, String> {
        val warmup = 30
        val samples = 250
        val total = warmup + samples
        val loopback = InetAddress.getByName("127.0.0.1")
        DatagramSocket(0, loopback).use { server ->
            server.soTimeout = 15_000
            var responderError: String? = null
            val responder = thread(name = "firewalldns-local-dns-responder") {
                try {
                    repeat(total) {
                        val incoming = DatagramPacket(ByteArray(512), 512)
                        server.receive(incoming)
                        val request = incoming.data.copyOf(incoming.length)
                        val response = positiveResponse(request)
                        server.send(DatagramPacket(response, response.size, incoming.socketAddress))
                    }
                } catch (error: Throwable) {
                    if (!server.isClosed) responderError = error.javaClass.simpleName
                }
            }

            val client = DnsUpstreamClient(
                DnsUpstreamConfig("127.0.0.1", server.localPort, timeoutMillis = 5_000),
                NoopSocketProtector,
            )
            repeat(warmup) { index ->
                val result = client.exchange(query("warm$index.device-bench.example", index))
                check(result is DnsUpstreamResult.Success) { "falló calentamiento: $result" }
            }

            val upstreamNanos = ArrayList<Long>(samples)
            var udpSuccesses = 0
            repeat(samples) { index ->
                val request = query("sample$index.device-bench.example", index + warmup)
                val started = System.nanoTime()
                val result = client.exchange(request)
                upstreamNanos += System.nanoTime() - started
                val success = result as? DnsUpstreamResult.Success
                check(success != null) { "falló consulta local: $result" }
                check(success.response.transport == DnsUpstreamTransport.UDP) { "transporte inesperado" }
                udpSuccesses++
            }
            responder.join(20_000)
            check(!responder.isAlive) { "el servidor DNS local no terminó" }
            check(responderError == null) { "falló el servidor DNS local: $responderError" }

            val cacheNanos = ArrayList<Long>(samples)
            var cacheSuccesses = 0
            repeat(samples) { index ->
                val request = query("sample${samples - 1}.device-bench.example", (index + 1) and 0xffff)
                val started = System.nanoTime()
                val result = client.exchange(request)
                cacheNanos += System.nanoTime() - started
                val success = result as? DnsUpstreamResult.Success
                check(success != null && success.response.transport == DnsUpstreamTransport.CACHE) {
                    "falló acierto de caché: $result"
                }
                cacheSuccesses++
            }

            val upstream = percentiles(upstreamNanos)
            val cache = percentiles(cacheNanos)
            val json = """
                {
                  "format": "firewalldns-device-diagnostic-v1",
                  "created_at_utc": "${Instant.now()}",
                  "device": {
                    "manufacturer": ${jsonString(Build.MANUFACTURER)},
                    "model": ${jsonString(Build.MODEL)},
                    "android_release": ${jsonString(Build.VERSION.RELEASE)},
                    "sdk_int": ${Build.VERSION.SDK_INT}
                  },
                  "scope": {
                    "network": "loopback_only",
                    "vpn_active": false,
                    "vpn_service_protect_measured": false,
                    "tun_traversal_measured": false,
                    "public_dns_measured": false,
                    "personal_dns_queries_collected": false
                  },
                  "configuration": {
                    "warmup_requests": $warmup,
                    "sample_count": $samples,
                    "resolver": "127.0.0.1",
                    "timeout_ms": 5000
                  },
                  "results": {
                    "udp_successes": $udpSuccesses,
                    "udp_p50_us": ${upstream[0]},
                    "udp_p95_us": ${upstream[1]},
                    "udp_p99_us": ${upstream[2]},
                    "cache_successes": $cacheSuccesses,
                    "cache_p50_us": ${cache[0]},
                    "cache_p95_us": ${cache[1]},
                    "cache_p99_us": ${cache[2]}
                  }
                }
            """.trimIndent()
            val summary = "Diagnóstico completado\n" +
                "DNS local UDP: $udpSuccesses/$samples correctas — P50 ${upstream[0]} µs, P95 ${upstream[1]} µs, P99 ${upstream[2]} µs\n" +
                "Caché: $cacheSuccesses/$samples correctas — P50 ${cache[0]} µs, P95 ${cache[1]} µs, P99 ${cache[2]} µs\n" +
                "Alcance: loopback local; no mide VPN activa ni red Wi-Fi/datos."
            return json to summary
        }
    }

    private fun exportReport() {
        val content = reportJson ?: return
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/json"
            putExtra(Intent.EXTRA_TITLE, "firewalldns-diagnostico.json")
        }
        pendingReport = content
        startActivityForResult(intent, CREATE_REPORT_REQUEST)
    }

    @Deprecated("Deprecated by Android API; retained for compatibility with minSdk 24")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == CREATE_REPORT_REQUEST && resultCode == RESULT_OK) {
            val uri = data?.data ?: return
            val content = pendingReport ?: return
            try {
                contentResolver.openOutputStream(uri)?.bufferedWriter()?.use { it.write(content) }
                status.append("\n\nInforme guardado. Adjunta ese archivo en esta conversación.")
            } catch (failure: Throwable) {
                status.append("\nNo se pudo guardar: ${failure.message}")
            }
        }
        pendingReport = null
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

    private fun percentiles(values: List<Long>): List<Long> {
        val sorted = values.sorted()
        fun at(p: Double): Long {
            val index = (kotlin.math.ceil(p * sorted.size).toInt() - 1).coerceIn(0, sorted.lastIndex)
            return sorted[index] / 1_000
        }
        return listOf(at(0.50), at(0.95), at(0.99))
    }

    private fun jsonString(value: String): String =
        "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\""

    private object NoopSocketProtector : DnsSocketProtector {
        override fun protect(socket: DatagramSocket): Boolean = true
        override fun protect(socket: Socket): Boolean = true
    }

    private companion object {
        const val CREATE_REPORT_REQUEST = 4107
        var pendingReport: String? = null
    }
}
