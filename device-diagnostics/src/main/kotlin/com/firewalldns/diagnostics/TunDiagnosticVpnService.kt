package com.firewalldns.diagnostics

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.time.Instant
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.concurrent.thread

/**
 * VPN isolated to the diagnostics APK. Only 198.18.0.1/32 is routed here.
 * It does not forward traffic, resolve DNS, or inspect other applications' packets.
 */
class TunDiagnosticVpnService : VpnService() {
    @Volatile private var tun: ParcelFileDescriptor? = null
    @Volatile private var reader: Thread? = null
    @Volatile private var running = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action != ACTION_START) {
            stopSelf(startId)
            return START_NOT_STICKY
        }
        startForeground(NOTIFICATION_ID, notification())
        try {
            val descriptor = Builder()
                .setSession("FirewallDNS TUN diagnóstico")
                .setMtu(1500)
                .addAddress("10.77.0.1", 32)
                .addRoute("198.18.0.1", 32)
                .establish()
            if (descriptor == null) {
                publishFailure("vpn_establish_returned_null", "Android no entregó el descriptor TUN")
                stopSelf(startId)
                return START_NOT_STICKY
            }
            tun = descriptor
            running = true
            startProbe(descriptor)
        } catch (failure: Throwable) {
            publishFailure("vpn_start_failed", failure.message ?: failure.javaClass.simpleName)
            stopSelf(startId)
        }
        return START_NOT_STICKY
    }

    private fun startProbe(descriptor: ParcelFileDescriptor) {
        val receivedAt = ConcurrentHashMap<Int, Long>()
        val sentAt = ConcurrentHashMap<Int, Long>()
        val completed = CountDownLatch(PROBE_COUNT)
        val readerReady = CountDownLatch(1)

        reader = thread(name = "firewalldns-diagnostic-tun-reader") {
            try {
                FileInputStream(descriptor.fileDescriptor).use { input ->
                    val buffer = ByteArray(32767)
                    // Wait until the TUN reader is ready before sending the first probe.
                    readerReady.countDown()
                    while (running && completed.count > 0) {
                        val length = input.read(buffer)
                        if (length <= 0) continue
                        val probe = Ipv4UdpProbeParser.parse(buffer, length) ?: continue
                        if (probe.sequence in 0 until PROBE_COUNT &&
                            receivedAt.putIfAbsent(probe.sequence, System.nanoTime()) == null
                        ) {
                            completed.countDown()
                        }
                    }
                }
            } catch (_: Throwable) {
                // Descriptor closure on service teardown releases this blocking read.
            }
        }

        thread(name = "firewalldns-diagnostic-tun-probes") {
            try {
                if (!readerReady.await(READER_READY_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                    throw IllegalStateException("El lector TUN no quedó listo a tiempo")
                }
                val protectSocket = DatagramSocket(null)
                val protectStarted = System.nanoTime()
                val protectResult = try {
                    protect(protectSocket)
                } finally {
                    protectSocket.close()
                }
                val protectElapsedUs = (System.nanoTime() - protectStarted) / 1_000

                var sendErrors = 0
                val destination = InetAddress.getByName("198.18.0.1")
                DatagramSocket().use { socket ->
                    repeat(PROBE_COUNT) { sequence ->
                        val payload = ByteArray(8)
                        writeInt(payload, 0, Ipv4UdpProbeParser.MAGIC)
                        writeInt(payload, 4, sequence)
                        sentAt[sequence] = System.nanoTime()
                        try {
                            socket.send(
                                DatagramPacket(
                                    payload,
                                    payload.size,
                                    destination,
                                    Ipv4UdpProbeParser.DESTINATION_PORT,
                                ),
                            )
                        } catch (_: Throwable) {
                            sentAt.remove(sequence)
                            sendErrors++
                        }
                        try {
                            Thread.sleep(PROBE_INTERVAL_MS)
                        } catch (_: InterruptedException) {
                            Thread.currentThread().interrupt()
                            throw IllegalStateException("Prueba interrumpida")
                        }
                    }
                }

                val allObserved = completed.await(PROBE_TIMEOUT_MS, TimeUnit.MILLISECONDS)
                running = false
                val latencies = receivedAt.entries.mapNotNull { (sequence, received) ->
                    sentAt[sequence]?.let { (received - it).coerceAtLeast(0L) }
                }.sorted()
                val report = buildReport(
                    protectResult,
                    protectElapsedUs,
                    PROBE_COUNT - sendErrors,
                    receivedAt.size,
                    sendErrors,
                    latencies,
                    allObserved,
                    (0 until PROBE_COUNT).filterNot { receivedAt.containsKey(it) },
                )
                publishResult(report)
            } catch (failure: Throwable) {
                running = false
                publishFailure("tun_probe_failed", failure.message ?: failure.javaClass.simpleName)
            } finally {
                stopSelf()
            }
        }
    }

    private fun buildReport(
        protectResult: Boolean,
        protectElapsedUs: Long,
        sent: Int,
        received: Int,
        sendErrors: Int,
        latencies: List<Long>,
        allObserved: Boolean,
        missingSequences: List<Int>,
    ): String {
        fun percentile(p: Double): Long {
            if (latencies.isEmpty()) return 0
            val index = (kotlin.math.ceil(p * latencies.size).toInt() - 1)
                .coerceIn(0, latencies.lastIndex)
            return latencies[index] / 1_000
        }
        val lost = (sent - received).coerceAtLeast(0)
        return """
            {
              "format": "firewalldns-tun-diagnostic-v1",
              "created_at_utc": "${Instant.now()}",
              "device": {
                "manufacturer": ${json(Build.MANUFACTURER)},
                "model": ${json(Build.MODEL)},
                "android_release": ${json(Build.VERSION.RELEASE)},
                "sdk_int": ${Build.VERSION.SDK_INT}
              },
              "scope": {
                "vpn_active": true,
                "diagnostic_vpn_only": true,
                "dns_used": false,
                "public_network_forwarding": false,
                "personal_dns_queries_collected": false,
                "route": "198.18.0.1/32",
                "measurement": "udp_send_to_tun_ingress"
              },
              "protect": {
                "socket_protect_returned": $protectResult,
                "elapsed_us": $protectElapsedUs
              },
              "tun": {
                "sent": $sent,
                "received": $received,
                "lost": $lost,
                "send_errors": $sendErrors,
                "missing_sequences": [${missingSequences.joinToString(",")}],
                "all_observed_before_timeout": $allObserved,
                "p50_us": ${percentile(0.50)},
                "p95_us": ${percentile(0.95)},
                "p99_us": ${percentile(0.99)}
              }
            }
        """.trimIndent()
    }

    private fun publishResult(json: String) {
        sendBroadcast(Intent(ACTION_RESULT).setPackage(packageName).putExtra(EXTRA_REPORT, json))
    }

    private fun publishFailure(stage: String, message: String) {
        val json = """{"format":"firewalldns-tun-diagnostic-failure-v1","stage":${json(stage)},"message":${json(message)},"vpn_active":false,"personal_dns_queries_collected":false}"""
        publishResult(json)
    }

    private fun notification(): Notification {
        val channelId = "firewalldns_tun_diagnostic"
        if (Build.VERSION.SDK_INT >= 26) {
            val channel = NotificationChannel(
                channelId,
                "Diagnóstico VPN",
                NotificationManager.IMPORTANCE_LOW,
            )
            getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
        }
        return if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(this, channelId)
                .setContentTitle("FirewallDNS - diagnóstico")
                .setContentText("Prueba aislada de entrada TUN en ejecución")
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setOngoing(true)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("FirewallDNS - diagnóstico")
                .setContentText("Prueba aislada de entrada TUN en ejecución")
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setOngoing(true)
                .build()
        }
    }

    override fun onDestroy() {
        running = false
        try {
            tun?.close()
        } catch (_: Throwable) {
        }
        tun = null
        reader?.interrupt()
        super.onDestroy()
    }

    private fun writeInt(target: ByteArray, offset: Int, value: Int) {
        target[offset] = (value ushr 24).toByte()
        target[offset + 1] = (value ushr 16).toByte()
        target[offset + 2] = (value ushr 8).toByte()
        target[offset + 3] = value.toByte()
    }

    private fun json(value: String): String =
        "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\""

    companion object {
        const val ACTION_START = "com.firewalldns.diagnostics.TUN_START"
        const val ACTION_RESULT = "com.firewalldns.diagnostics.TUN_RESULT"
        const val EXTRA_REPORT = "report_json"
        private const val NOTIFICATION_ID = 7731
        private const val PROBE_COUNT = 100
        private const val PROBE_INTERVAL_MS = 8L
        private const val PROBE_TIMEOUT_MS = 8_000L
        private const val READER_READY_TIMEOUT_MS = 2_000L
    }
}
