package com.firewalldns.diagnostics

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import java.net.DatagramSocket
import kotlin.concurrent.thread

class UdpTunBridgeDiagnosticService : VpnService() {
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_START) {
            startForegroundCompat()
            thread(name = "firewalldns-udp-bridge-diag") {
                val report = runBridgeDiagnostic()
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

    private fun runBridgeDiagnostic(): String = try {
        val builder = Builder()
            .setSession("FirewallDNS UDP Bridge Diagnostic")
            .setMtu(1500)
            .addAddress("10.77.2.2", 32)
            .addRoute("10.77.2.1", 32)
        val pfd = builder.establish() ?: error("tun_establish_returned_null")
        pfd.use {
            var protectedOk = false
            DatagramSocket().use { socket ->
                protectedOk = protect(socket)
            }
            """
            {
              "format": "firewalldns-udp-tun-bridge-v1",
              "created_at_utc": "${currentUtcIsoTimestamp()}",
              "tun_established": true,
              "socket_protected": $protectedOk
            }
            """.trimIndent()
        }
    } catch (t: Throwable) {
        """
        {
          "format": "firewalldns-udp-tun-bridge-failure-v1",
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
                .setContentTitle("FirewallDNS UDP Bridge Diagnostic")
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .build()
            startForeground(103, notification)
        }
    }

    companion object {
        const val ACTION_START = "com.firewalldns.diagnostics.UDP_BRIDGE_START"
        const val ACTION_RESULT = "com.firewalldns.diagnostics.UDP_BRIDGE_RESULT"
        const val EXTRA_REPORT = "report"
    }
}
