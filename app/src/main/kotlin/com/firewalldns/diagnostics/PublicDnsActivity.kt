package com.firewalldns.diagnostics

import android.annotation.SuppressLint
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
import org.json.JSONObject
import kotlin.concurrent.thread

class PublicDnsActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var runButton: Button
    private lateinit var exportButton: Button
    private lateinit var failoverButton: Button
    private lateinit var tunButton: Button
    private lateinit var engineTunButton: Button
    private lateinit var stopEngineTunButton: Button
    private lateinit var prodVpnButton: Button
    private lateinit var stopProdVpnButton: Button
    @Volatile private var report: String? = null
    @Volatile private var engineTunReport: String? = null
    private var engineTunStartedAtElapsed = 0L
    private var prodVpnStartedAtElapsed = 0L
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
            val tcpActive = intent.getIntExtra("dns_tcp_sessions_active", 0)
            val tcpAccepted = intent.getLongExtra("dns_tcp_accepted", 0)
            val tcpQueries = intent.getLongExtra("dns_tcp_queries_processed", 0)
            val tcpRetrans = intent.getLongExtra("dns_tcp_retransmissions", 0)
            val tcpFastRetrans = intent.getLongExtra("dns_tcp_fast_retransmissions", 0)
            val tcpZeroWindow = intent.getLongExtra("dns_tcp_zero_window_events", 0)
            val tcpClosed = intent.getLongExtra("dns_tcp_closed_gracefully", 0)
            val tcpResets = intent.getLongExtra("dns_tcp_resets", 0)
            val tcpRejectedLimit = intent.getLongExtra("dns_tcp_rejected_limit", 0)
            val updatedAt = intent.getLongExtra("updated_at_elapsed_ms", android.os.SystemClock.elapsedRealtime())
            val trafficClassification = intent.getStringExtra("traffic_classification") ?: "{}"
            val startedAt = engineTunStartedAtElapsed.takeIf { it > 0L } ?: updatedAt
            val durationMs = (updatedAt - startedAt).coerceAtLeast(0L)
            engineTunReport = """{
  "format": "firewalldns-engine-tun-diagnostic",
  "schema_version": 3,
  "state": "$state",
  "duration_ms": $durationMs,
  "device": {
    "manufacturer": ${JSONObject.quote(Build.MANUFACTURER)},
    "model": ${JSONObject.quote(Build.MODEL)},
    "android_release": ${JSONObject.quote(Build.VERSION.RELEASE)},
    "sdk_int": ${Build.VERSION.SDK_INT}
  },
  "coverage": {
    "capture_mode": "dns_virtual_routes_only",
    "default_routes_enabled": false,
    "ipv4_route": "10.77.0.1/32",
    "ipv6_route": "fd77::1/128",
    "full_device_capture": false,
    "tcp_udp_scope": "only packets actually delivered to these DNS virtual TUN routes",
    "flow_tracking_enabled": true,
    "application_identity_enabled": false
  },
  "traffic_classification": $trafficClassification,
  "capabilities": {
    "packet_classification": true,
    "dns_over_tcp_sessions": true,
    "tcp_udp_general_capture": false,
    "tcp_forwarding": false,
    "udp_forwarding": false,
    "flow_tracking": true,
    "application_uid_attribution": false,
    "icmp_forwarding": false,
    "fragment_reassembly": false,
    "tls_decryption": false,
    "doh_dot_semantic_inspection": false,
    "cpu_memory_battery_metrics": false,
    "unsupported_reason": "The current diagnostic VPN routes only virtual DNS endpoints (UDP/53 + TCP/53); general forwarding is intentionally disabled until a tested transport plane is available."
  },
  "dns_over_tcp": {
    "sessions_active": $tcpActive,
    "sessions_accepted": $tcpAccepted,
    "queries_processed": $tcpQueries,
    "retransmissions": $tcpRetrans,
    "fast_retransmissions": $tcpFastRetrans,
    "zero_window_events": $tcpZeroWindow,
    "closed_gracefully": $tcpClosed,
    "resets": $tcpResets,
    "rejected_limit": $tcpRejectedLimit
  },
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
    "payloads_stored": false,
    "domains_stored": false,
    "addresses_stored": false,
    "uids_or_package_names_stored": false,
    "domain_names_recorded": false,
    "packet_payloads_recorded": false
  },
  "updated_at_elapsed_ms": $updatedAt
}"""
            report = engineTunReport
            status.text = "Motor propio en TUN: $state\nPaquetes recibidos: $packets\nRespuestas procesadas: $processed\nRespuestas enviadas: $sent\nProcesador con respuesta: $processorReturned | Sin respuesta: $processorNoResponse | Excepción: $processorFailed\nCola saturada: $queueRejected | Error al escribir: $responseWriteFailed | Detenidos antes de responder: $stoppedBeforeResponse\nDNS-TCP activas: $tcpActive | Aceptadas: $tcpAccepted | Consultas: $tcpQueries | Retrans: $tcpRetrans (fast: $tcpFastRetrans) | Win0: $tcpZeroWindow | FIN: $tcpClosed | RST: $tcpResets\nBLOCK: $blocked | OBSERVE: $observed | ALLOW: $allowed\nRechazados: $rejected\nDescartados (suma de causas): $dropped\nDuración: ${durationMs / 1000}s\n\nPulsa «Guardar informe JSON» para exportar estos datos. Se actualizan cada 0,5 segundos.\n\nSolo se enruta al túnel el DNS (UDP/TCP 53) dirigido a sus direcciones virtuales."
            exportButton.isEnabled = true
            engineTunButton.isEnabled = state != "running" && state != "starting"
            stopEngineTunButton.isEnabled = state == "running" || state == "starting" || state == "stopping"
        }
    }

    private val prodVpnReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            val state = intent?.getStringExtra(FirewallDnsVpnService.EXTRA_STATE) ?: return
            val packets = intent.getLongExtra("packets_in", 0)
            val sent = intent.getLongExtra("responses_out", 0)
            val blocked = intent.getLongExtra("blocked", 0)
            val observed = intent.getLongExtra("observed", 0)
            val allowed = intent.getLongExtra("allowed", 0)
            val rejected = intent.getLongExtra("rejected", 0)
            val protectOk = intent.getBooleanExtra("protect_verified", false)
            val loopFreeOk = intent.getBooleanExtra("loop_free_verified", false)
            val zeroLeaksOk = intent.getBooleanExtra("zero_dns_leaks_verified", false)
            val loopsBlocked = intent.getLongExtra("loops_blocked", 0)
            val leaksBlocked = intent.getLongExtra("dns_leaks_blocked", 0)
            val protectFailClosed = intent.getLongExtra("protect_fail_closed", 0)
            val protectUdpOk = intent.getLongExtra("protect_udp_successes", 0)
            val protectTcpOk = intent.getLongExtra("protect_tcp_successes", 0)
            val protectFailures = intent.getLongExtra("protect_failures", 0)
            val fragsReassembled = intent.getLongExtra("fragments_reassembled", 0)
            val tcpActive = intent.getIntExtra("dns_tcp_sessions_active", 0)
            val tcpQueries = intent.getLongExtra("dns_tcp_queries_processed", 0)
            val tcpRetrans = intent.getLongExtra("dns_tcp_retransmissions", 0)
            val validationJson = intent.getStringExtra("validation_json") ?: "{}"
            val trafficClassification = intent.getStringExtra("traffic_classification") ?: "{}"
            val updatedAt = intent.getLongExtra("updated_at_elapsed_ms", android.os.SystemClock.elapsedRealtime())
            val startedAt = prodVpnStartedAtElapsed.takeIf { it > 0L } ?: updatedAt
            val durationMs = (updatedAt - startedAt).coerceAtLeast(0L)
            report = """{
  "format": "firewalldns-production-data-plane",
  "schema_version": 4,
  "state": "$state",
  "duration_ms": $durationMs,
  "device": {
    "manufacturer": ${JSONObject.quote(Build.MANUFACTURER)},
    "model": ${JSONObject.quote(Build.MODEL)},
    "android_release": ${JSONObject.quote(Build.VERSION.RELEASE)},
    "sdk_int": ${Build.VERSION.SDK_INT}
  },
  "security_validation": $validationJson,
  "runtime_guards": {
    "protect_udp_successes": $protectUdpOk,
    "protect_tcp_successes": $protectTcpOk,
    "protect_failures": $protectFailures,
    "protect_fail_closed_blocked": $protectFailClosed,
    "loops_blocked": $loopsBlocked,
    "dns_leaks_blocked": $leaksBlocked
  },
  "data_plane": {
    "packets_in": $packets,
    "responses_out": $sent,
    "fragments_reassembled": $fragsReassembled,
    "dns_tcp_sessions_active": $tcpActive,
    "dns_tcp_queries_processed": $tcpQueries,
    "dns_tcp_retransmissions": $tcpRetrans,
    "blocked": $blocked,
    "observed": $observed,
    "allowed": $allowed,
    "rejected": $rejected
  },
  "traffic_classification": $trafficClassification,
  "updated_at_elapsed_ms": $updatedAt
}"""
            status.text = "Plano de datos en producción: $state\nValidación preflight -> protect(): $protectOk | Sin bucles: $loopFreeOk | Cero fugas DNS: $zeroLeaksOk\nProtect UDP/TCP OK: $protectUdpOk/$protectTcpOk (fallos: $protectFailures, fail-closed: $protectFailClosed)\nBucles bloqueados: $loopsBlocked | Fugas DoT bloqueadas: $leaksBlocked | Fragmentos reensamblados: $fragsReassembled\nPaquetes: $packets | Respuestas: $sent | DNS-TCP activas/consultas: $tcpActive/$tcpQueries (retrans: $tcpRetrans)\nBLOCK: $blocked | OBSERVE: $observed | ALLOW: $allowed | Rechazados: $rejected\nDuración: ${durationMs / 1000}s"
            exportButton.isEnabled = true
            prodVpnButton.isEnabled = state != "running" && state != "validating"
            stopProdVpnButton.isEnabled = state == "running" || state == "validating" || state == "stopping"
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
            text = "Diagnóstico Integral FirewallDNS — informe único v3"
            textSize = 23f
        })
        root.addView(TextView(this).apply {
            text = "Una sola sesión y un solo JSON: clasifica los paquetes que llegan al TUN, agrega protocolos, motivos, bytes y latencias, y registra el alcance real de la captura. Antes de iniciar, desactiva FirewallDNS y cualquier otra VPN."
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
        engineTunButton = Button(this).apply {
            text = "Iniciar diagnóstico integral (un solo informe)"
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
        prodVpnButton = Button(this).apply {
            text = "Validar e iniciar plano de datos en producción"
            setOnClickListener { requestProdVpn() }
        }
        stopProdVpnButton = Button(this).apply {
            text = "Detener plano de producción"
            isEnabled = false
            setOnClickListener {
                isEnabled = false
                status.text = "Deteniendo plano de datos en producción…"
                val stop = Intent(this@PublicDnsActivity, FirewallDnsVpnService::class.java)
                    .setAction(FirewallDnsVpnService.ACTION_STOP)
                startService(stop)
            }
        }
        root.addView(status, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        root.addView(prodVpnButton)
        root.addView(stopProdVpnButton)
        root.addView(runButton)
        root.addView(failoverButton)
        root.addView(tunButton)
        root.addView(exportButton)
        root.addView(engineTunButton)
        root.addView(stopEngineTunButton)
        root.addView(localButton)
        setContentView(ScrollView(this).apply { addView(root) })
    }

    override fun onStart() {
        super.onStart()
        val filter = IntentFilter(TunDiagnosticVpnService.ACTION_RESULT)
        registerInternalReceiver(tunResultReceiver, filter)
        receiverRegistered = true
        engineTunButton.isEnabled = true
        stopEngineTunButton.isEnabled = false
        prodVpnButton.isEnabled = true
        stopProdVpnButton.isEnabled = false
        val engineFilter = IntentFilter(EngineTunVpnService.ACTION_STATUS)
        registerInternalReceiver(engineTunReceiver, engineFilter)
        val prodFilter = IntentFilter(FirewallDnsVpnService.ACTION_STATUS)
        registerInternalReceiver(prodVpnReceiver, prodFilter)
    }

    @SuppressLint("UnspecifiedRegisterReceiverFlag")
    private fun registerInternalReceiver(receiver: BroadcastReceiver, filter: IntentFilter) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(receiver, filter)
        }
    }

    override fun onStop() {
        if (receiverRegistered) {
            unregisterReceiver(tunResultReceiver)
            unregisterReceiver(engineTunReceiver)
            unregisterReceiver(prodVpnReceiver)
            receiverRegistered = false
        }
        super.onStop()
    }

    private fun requestTunDiagnostic() {
        val consentIntent = VpnService.prepare(this)
        if (consentIntent != null) {
            @Suppress("DEPRECATION")
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
            @Suppress("DEPRECATION")
            startActivityForResult(consentIntent, ENGINE_TUN_CONSENT_REQUEST)
        } else {
            startEngineTunService()
        }
    }

    private fun requestProdVpn() {
        val consentIntent = VpnService.prepare(this)
        if (consentIntent != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(consentIntent, PROD_VPN_CONSENT_REQUEST)
        } else {
            startProdVpnService()
        }
    }

    private fun startProdVpnService() {
        prodVpnButton.isEnabled = false
        stopProdVpnButton.isEnabled = true
        prodVpnStartedAtElapsed = android.os.SystemClock.elapsedRealtime()
        report = null
        exportButton.isEnabled = false
        status.text = "Validando VpnService.protect(), ausencia de bucles y cero fugas DNS para iniciar el plano de datos en producción…"
        val start = Intent(this, FirewallDnsVpnService::class.java)
            .setAction(FirewallDnsVpnService.ACTION_START)
        if (Build.VERSION.SDK_INT >= 26) startForegroundService(start) else startService(start)
    }

    private fun startEngineTunService() {
        engineTunButton.isEnabled = false
        stopEngineTunButton.isEnabled = true
        engineTunStartedAtElapsed = android.os.SystemClock.elapsedRealtime()
        engineTunReport = null
        report = null
        exportButton.isEnabled = false
        status.text = "Iniciando VPN DNS de diagnóstico con FirewallDNS-Engine. Desactiva antes cualquier otra VPN."
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
                    status.text = result.second + "\n\nGuarda el JSON y envíamelo."
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
                    status.text = result.second + "\n\nGuarda el JSON."
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
            content.contains("firewalldns-production-data-plane") -> "firewalldns-produccion-plano-datos.json"
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
        @Suppress("DEPRECATION")
        startActivityForResult(intent, SAVE_REPORT_REQUEST)
    }

    @Deprecated("Deprecated by Android API; retained for compatibility")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == PROD_VPN_CONSENT_REQUEST) {
            if (resultCode == RESULT_OK) {
                startProdVpnService()
            } else {
                status.text = "Permiso VPN denegado. No se inició el plano de datos en producción."
                prodVpnButton.isEnabled = true
                stopProdVpnButton.isEnabled = false
            }
            return
        }
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
                status.append("\n\nInforme guardado.")
            } catch (failure: Throwable) {
                status.append("\nNo se pudo guardar: ${failure.message}")
            }
        }
        pendingReport = null
    }

    private companion object {
        const val PROD_VPN_CONSENT_REQUEST = 4111
        const val ENGINE_TUN_CONSENT_REQUEST = 4110
        const val TUN_CONSENT_REQUEST = 4109
        const val SAVE_REPORT_REQUEST = 4108
        var pendingReport: String? = null
    }
}
