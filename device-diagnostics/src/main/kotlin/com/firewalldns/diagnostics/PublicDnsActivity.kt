package com.firewalldns.diagnostics

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import kotlin.concurrent.thread

/** Public resolver test entry point. The existing loopback benchmark remains available. */
class PublicDnsActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var runButton: Button
    private lateinit var exportButton: Button
    private lateinit var failoverButton: Button
    @Volatile private var report: String? = null

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
            text = "Consulta dos resolutores públicos (Cloudflare y Google) mediante UDP/53. No cambia los DNS del teléfono. Ejecuta una vez con Wi-Fi y otra con datos móviles, cambiando la conexión manualmente entre pruebas. Mantén FirewallDNS apagado."
            textSize = 16f
            setPadding(0, 20, 0, 20)
        })
        status = TextView(this).apply {
            text = "Listo. Se harán 30 mediciones por resolutor, con 3 calentamientos."
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
        val localButton = Button(this).apply {
            text = "Abrir diagnóstico local del motor"
            setOnClickListener { startActivity(Intent(this@PublicDnsActivity, MainActivity::class.java)) }
        }
        root.addView(status, ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT)
        root.addView(runButton)
        root.addView(exportButton)
        root.addView(failoverButton)
        root.addView(localButton)
        setContentView(ScrollView(this).apply { addView(root) })
    }

    private fun runTest() {
        runButton.isEnabled = false
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
                    exportButton.isEnabled = true
                }
            } catch (failure: Throwable) {
                runOnUiThread {
                    status.text = "No se pudo completar: ${failure.javaClass.simpleName}: ${failure.message ?: "sin detalle"}"
                    runButton.isEnabled = true
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
                    status.text = result.second + "\\n\\nGuarda el JSON. Repite una vez en Wi-Fi y otra en datos móviles."
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
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/json"
            putExtra(Intent.EXTRA_TITLE, "firewalldns-dns-publico.json")
        }
        pendingReport = content
        startActivityForResult(intent, 4108)
    }

    @Deprecated("Deprecated by Android API; retained for compatibility")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == 4108 && resultCode == RESULT_OK) {
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
        var pendingReport: String? = null
    }
}
