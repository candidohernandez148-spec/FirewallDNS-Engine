package com.firewalldns.diagnostics

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import java.net.DatagramSocket
import kotlin.concurrent.thread

class TunDiagnosticVpnService : VpnService() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_START) {
            startForegroundCompat()
            thread(name = "firewalldns-tun-diag") {
                val report = runDiagnostic()
                sendBroadcast(
                    Intent(ACTION_RESULT).apply {
                        setPackage(packageName)
                        putExtra(EXTRA_REPORT, report)
                    },
                )
                if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
        return START_NOT_STICKY
    }

    private fun runDiagnostic(): String = try {
        val builder = Builder()
            .setSession("FirewallDNS TUN Protect Diagnostic")
            .setMtu(1500)
            .addAddress("10.77.1.2", 32)
            .addRoute("10.77.1.1", 32)
        val pfd = builder.establish() ?: error("tun_establish_returned_null")
        pfd.use {
            var protectSuccesses = 0
            repeat(100) {
                DatagramSocket().use { socket ->
                    if (protect(socket)) protectSuccesses++
                }
            }
            """
            {
              "format": "firewalldns-tun-diagnostic-v1",
              "created_at_utc": "${currentUtcIsoTimestamp()}",
              "protect_samples": 100,
              "protect_successes": $protectSuccesses
            }
            """.trimIndent()
        }
    } catch (t: Throwable) {
        """
        {
          "format": "firewalldns-tun-diagnostic-failure-v1",
          "created_at_utc": "${currentUtcIsoTimestamp()}",
          "error": "${t.javaClass.simpleName}: ${t.message}"
        }
        """.trimIndent()
    }

    private fun startForegroundCompat() {
        val channelId = "firewalldns_diag_tun"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            nm?.createNotificationChannel(
                NotificationChannel(channelId, "FirewallDNS Diagnostics", NotificationManager.IMPORTANCE_LOW),
            )
            val notification = Notification.Builder(this, channelId)
                .setContentTitle("FirewallDNS TUN Diagnostic")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .build()
            startForeground(102, notification)
        }
    }

    companion object {
        const val ACTION_START = "com.firewalldns.diagnostics.TUN_DIAG_START"
        const val ACTION_RESULT = "com.firewalldns.diagnostics.TUN_DIAG_RESULT"
        const val EXTRA_REPORT = "report"
    }
}
