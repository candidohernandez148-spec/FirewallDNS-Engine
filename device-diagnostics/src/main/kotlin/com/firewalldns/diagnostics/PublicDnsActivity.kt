package com.firewalldns.diagnostics

import android.app.Activity
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import kotlin.concurrent.thread

/** Public resolver tests and isolated VpnService/TUN diagnostic launcher. */
class PublicDnsActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var runButton: Button
    private lateinit var exportButton: Button
    private lateinit var failoverButton: Button
    private lateinit var tunButton: Button
    private lateinit var engineTunButton: Button
    private lateinit var stopEngineTunButton: Button
    @Volatile private var report: String? = null
    @Volatile private var engineTunReport: String? = null
    private var engineTunStartedAtElapsed = 0L
    private var receiverRegistered = false

    private val tunResultReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val json = intent?.getStringExtra(TunDiagnosticVpnService.EXTRA_REPORT) ?: return
            report = json
            status.text = if (json.contains("tun-diagnostic-failure")) {
                "La prueba TUN no pudo completarse. Guarda el informe para revisar el error.\n\n$json"
            } else {
                "Prueba TUN completada. Guarda el JSON y envíamelo.\n\n$json"
            }
            exportButton.isEnabled = true
            tunButton.isEnabled = true
        }
    }

    private val engineTunReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val state = intent?.getStringExtra(EngineTunVpnService.EXTRA_STATE) ?: return
            val packets = intent.getLongExtra("packets_in", 0)
            val processed = intent.getLongExtra("dns_processed", 0)
            val sent = intent.getLongExtra("responses_out", 0)
            val dropped = intent.getLongExtra("dropped", 0)
            val processorReturned = intent.getLongExtra("processor_returned_response", 0)
            val processorNoResponse = intent.getLongExtra("processor_no_response", 0)
            val processorFailed = intent.getLongExtra("processor_failed", 0)
            val queueRejected = intent.getLongExtra("queue_rejected", 0)
            val responseWriteFailed = intent.getLongExtra("response_write_failed", 0)
            val stoppedBeforeResponse = intent.getLongExtra("stopped_before_response", 0)
            val blocked = intent.getLongExtra("blocked", 0)
            val observed = intent.getLongExtra("observed", 0)
            val allowed = intent.getLongExtra("allowed", 0)
            val rejected = intent.getLongExtra("rejected", 0)
            val updatedAt = intent.getLongExtra("updated_at_elapsed_ms", android.os.SystemClock.elapsedRealtime())
            val startedAt = engineTunStartedAtElapsed.takeIf { it > 0L } ?: updatedAt
            val durationMs = (updatedAt - startedAt).coerceAtLeast(0L)
            engineTunReport = """{
  "format": "firewalldns-engine-tun-diagnostic",
  "schema_version": 2,
  "state": "$state",
  "duration_ms": $durationMs,
  "metrics": {
    "packets_in": $packets,
    "dns_processed": $processed,
    "responses_out": $sent,
    "processor_returned_response": $processorReturned,
    "processor_no_response": $processorNoResponse,
    "processor_failed": $processorFailed,
    "queue_rejected": $queueRejected,
    "response_write_failed": $responseWriteFailed,
    "stopped_before_response": $stoppedBeforeResponse,
    "blocked": $blocked,
    "observed": $observed,
    "allowed": $allowed,
    "rejected": $rejected,
    "dropped": $dropped
  },
  "privacy": {
    "domain_names_recorded": false,
    "packet_payloads_recorded": false
  },
  "updated_at_elapsed_ms": $updatedAt
}"""
            report = engineTunReport
            status.text = "Motor propio en TUN: $state\nPaquetes recibidos: $packets\nRespuestas procesadas: $processed\nRespuestas enviadas: $sent\nProcesador con respuesta: $processorReturned | Sin respuesta: $processorNoResponse | Excepción: $processorFailed\nCola saturada: $queueRejected | Error al escribir: $responseWriteFailed | Detenidos antes de responder: $stoppedBeforeResponse\nBLOCK: $blocked | OBSERVE: $observed | ALLOW: $allowed\nRechazados: $rejected\nDescartados (suma de causas): $dropped\nDuración: ${durationMs / 1000}s\n\nPulsa «Guardar informe JSON» para exportar estos datos. Se actualizan cada 0,5 segundos.\n\nSolo se enruta al túnel el DNS dirigido a sus direcciones virtuales; no es un firewall de todo el tráfico."
            exportButton.isEnabled = true
            engineTunButton.isEnabled = state != "running" && state != "starting"
            stopEngineTunButton.isEnabled = state == "running" || state == "starting" || state == "stopping"
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        title = "FirewallDNS - Prueba de red"
        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 32, 32, 32)
        }
        root.addView(TextView(this).apply {
            text = "Diagnóstico DNS de red real"
            textSize = 23f
        })
        root.addView(TextView(this).apply {
            text = "Consulta dos resolutores públicos (Cloudflare y Google) mediante UDP/53. No cambia los DNS del teléfono. Para medir TUN, apaga FirewallDNS y cualquier otra VPN: Android activará temporalmente una VPN exclusiva de diagnóstico y la detendrá al terminar."
            textSize = 16f
            setPadding(0, 20, 0, 20)
        })
        status = TextView(this).apply {
            text = "Listo. Se harán 30 mediciones por resolutor, con 3 calentamientos.\n\nEl estado y los contadores del motor se actualizarán automáticamente mientras el TUN esté activo."
            textSize = 15f
            setPadding(0, 12, 0, 24)
        }
        runButton = Button(this).apply {
            text = "Probar conexión actual"
            setOnClickListener { runTest() }
        }
        exportButton = Button(this).apply {
            text = "Guardar informe JSON"
            isEnabled = false
            setOnClickListener { saveReport() }
        }
        failoverButton = Button(this).apply {
            text = "Probar failover real del motor"
            setOnClickListener { runFailoverTest() }
        }
        tunButton = Button(this).apply {
            text = "Medir VpnService.protect() y entrada TUN"
            setOnClickListener { requestTunDiagnostic() }
        }
        val localButton = Button(this).apply {
            text = "Abrir diagnóstico local del motor"
            setOnClickListener { startActivity(Intent(this@PublicDnsActivity, MainActivity::class.java)) }
        }
        root.addView(status, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        root.addView(runButton)
        root.addView(exportButton)
        root.addView(failoverButton)
        root.addView(tunButton)
        engineTunButton = Button(this).apply {
            text = "Probar TUN con nuestro motor DNS real"
            setOnClickListener { requestEngineTun() }
        }
        stopEngineTunButton = Button(this).apply {
            text = "Detener motor TUN"
            isEnabled = false
            setOnClickListener {
                isEnabled = false
                status.text = "Deteniendo VPN del motor y cerrando el descriptor TUN…"
                val stop = Intent(this@PublicDnsActivity, EngineTunVpnService::class.java)
                    .setAction(EngineTunVpnService.ACTION_STOP)
                startService(stop)
            }
        }
        root.addView(engineTunButton)
        root.addView(stopEngineTunButton)
        root.addView(localButton)
        setContentView(ScrollView(this).apply { addView(root) })
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(TunDiagnosticVpnService.ACTION_RESULT)
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(tunResultReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(tunResultReceiver, filter)
        }
        receiverRegistered = true
        engineTunButton.isEnabled = true
        stopEngineTunButton.isEnabled = false
        val engineFilter = IntentFilter(EngineTunVpnService.ACTION_STATUS)
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(engineTunReceiver, engineFilter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(engineTunReceiver, engineFilter)
        }
    }

    override fun onStop() {
        if (receiverRegistered) {
            unregisterReceiver(tunResultReceiver)
            unregisterReceiver(engineTunReceiver)
            receiverRegistered = false
        }
        super.onStop()
    }

    private fun requestTunDiagnostic() {
        val consentIntent = VpnService.prepare(this)
        if (consentIntent != null) {
            startActivityForResult(consentIntent, TUN_CONSENT_REQUEST)
        } else {
            startTunService()
        }
    }

    private fun startTunService() {
        tunButton.isEnabled = false
        exportButton.isEnabled = false
        report = null
        status.text = "Solicitando TUN de diagnóstico y enviando 100 paquetes sintéticos…"
        val intent = Intent(this, TunDiagnosticVpnService::class.java)
            .setAction(TunDiagnosticVpnService.ACTION_START)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(intent) else startService(intent)
    }

    private fun requestEngineTun() {
        val consentIntent = VpnService.prepare(this)
        if (consentIntent != null) {
            startActivityForResult(consentIntent, ENGINE_TUN_CONSENT_REQUEST)
        } else {
            startEngineTunService()
        }
    }

    private fun startEngineTunService() {
        engineTunButton.isEnabled = false
        stopEngineTunButton.isEnabled = true
        engineTunStartedAtElapsed = android.os.SystemClock.elapsedRealtime()
        engineTunReport = null
        report = null
        exportButton.isEnabled = false
        status.text = "Iniciando VPN DNS de diagnóstico con FirewallDNS-Engine. Desactiva antes cualquier otra VPN. No se modifica el DNS global del teléfono."
        val start = Intent(this, EngineTunVpnService::class.java)
            .setAction(EngineTunVpnService.ACTION_START)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(start) else startService(start)
    }

    private fun runTest() {
        runButton.isEnabled = false
        failoverButton.isEnabled = false
        exportButton.isEnabled = false
        report = null
        status.text = "Consultando resolutores públicos…"
        thread(name = "firewalldns-public-dns-test") {
            try {
                val result = PublicDnsBenchmark.execute(this)
                report = result.first
                runOnUiThread {
                    status.text = result.second + "\n\nGuarda el JSON y envíamelo. Después cambia de Wi-Fi a datos móviles (o al revés) y repite."
                    runButton.isEnabled = true
                    failoverButton.isEnabled = true
                    exportButton.isEnabled = true
                }
            } catch (failure: Throwable) {
                runOnUiThread {
                    status.text = "No se pudo completar: ${failure.javaClass.simpleName}: ${failure.message ?: "sin detalle"}"
                    runButton.isEnabled = true
                    failoverButton.isEnabled = true
                }
            }
        }
    }

    private fun runFailoverTest() {
        runButton.isEnabled = false
        failoverButton.isEnabled = false
        exportButton.isEnabled = false
        report = null
        status.text = "Probando failover del motor…"
        thread(name = "firewalldns-engine-failover-test") {
            try {
                val result = FailoverDnsBenchmark.execute(this)
                report = result.first
                runOnUiThread {
                    status.text = result.second + "\n\nGuarda el JSON. Repite una vez en Wi-Fi y otra en datos móviles."
                    runButton.isEnabled = true
                    failoverButton.isEnabled = true
                    exportButton.isEnabled = true
                }
            } catch (failure: Throwable) {
                runOnUiThread {
                    status.text = "Falló la prueba de failover: ${failure.javaClass.simpleName}: ${failure.message ?: "sin detalle"}"
                    runButton.isEnabled = true
                    failoverButton.isEnabled = true
                }
            }
        }
    }

    private fun saveReport() {
        val content = report ?: return
        val filename = when {
            content.contains("firewalldns-engine-tun-diagnostic") -> "firewalldns-engine-tun-diagnostico.json"
            content.contains("firewalldns-tun-diagnostic") -> "firewalldns-diagnostico-tun.json"
            else -> "firewalldns-dns-publico.json"
        }
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/json"
            putExtra(Intent.EXTRA_TITLE, filename)
        }
        pendingReport = content
        startActivityForResult(intent, SAVE_REPORT_REQUEST)
    }

    @Deprecated("Deprecated by Android API; retained for compatibility")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == ENGINE_TUN_CONSENT_REQUEST) {
            if (resultCode == RESULT_OK) {
                startEngineTunService()
            } else {
                status.text = "Permiso VPN denegado. No se inició el TUN del motor."
                engineTunButton.isEnabled = true
                stopEngineTunButton.isEnabled = false
            }
            return
        }
        if (requestCode == TUN_CONSENT_REQUEST) {
            if (resultCode == RESULT_OK) {
                startTunService()
            } else {
                status.text = "Permiso VPN denegado. No se inició la prueba TUN."
                tunButton.isEnabled = true
            }
            return
        }
        if (requestCode == SAVE_REPORT_REQUEST && resultCode == RESULT_OK) {
            val uri = data?.data ?: return
            val content = pendingReport ?: return
            try {
                contentResolver.openOutputStream(uri)?.bufferedWriter()?.use { it.write(content) }
                status.append("\n\nInforme guardado. Adjunta el archivo en esta conversación.")
            } catch (failure: Throwable) {
                status.append("\nNo se pudo guardar: ${failure.message}")
            }
        }
        pendingReport = null
    }

    private companion object {
        const val ENGINE_TUN_CONSENT_REQUEST = 4110
        const val TUN_CONSENT_REQUEST = 4109
        const val SAVE_REPORT_REQUEST = 4108
        var pendingReport: String? = null
    }
}
