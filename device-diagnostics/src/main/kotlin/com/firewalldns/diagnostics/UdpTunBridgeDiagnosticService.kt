package com.firewalldns.diagnostics

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import com.firewalldns.engine.android.AndroidDnsSocketProtector
import com.firewalldns.engine.android.AndroidProtectedUdpSocketFactory
import com.firewalldns.engine.android.AndroidUdpFlowManager
import com.firewalldns.engine.android.AndroidUdpTunBridge
import com.firewalldns.engine.android.UdpTunPacketResult
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

/**
 * On-device diagnostic for TUN -> VpnService.protect() UDP socket -> TUN.
 * Traffic is restricted to a synthetic destination and a loopback echo peer.
 * It does not contact public hosts, capture DNS, or change the production VPN.
 */
class UdpTunBridgeDiagnosticService : VpnService() {
    @Volatile private var descriptor: ParcelFileDescriptor? = null
    @Volatile private var reader: Thread? = null
    @Volatile private var bridge: AndroidUdpTunBridge? = null
    @Volatile private var echoServer: DatagramSocket? = null
    private val running = AtomicBoolean(false)
    private val packetsIn = AtomicLong()
    private val responsesOut = AtomicLong()
    private val unsupported = AtomicLong()
    private val rejected = AtomicLong()
    private val writeLock = Any()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopDiagnostic()
            stopSelfResult(startId)
            return START_NOT_STICKY
        }
        if (intent?.action != ACTION_START || running.get()) {
            if (!running.get()) stopSelf(startId)
            return START_NOT_STICKY
        }
        startForeground(NOTIFICATION_ID, notification())
        try {
            startDiagnostic()
        } catch (failure: Throwable) {
            publishFailure("start_failed", failure.message ?: failure.javaClass.simpleName)
            stopDiagnostic()
            stopSelfResult(startId)
        }
        return START_NOT_STICKY
    }

    private fun startDiagnostic() {
        val peer = DatagramSocket(null).apply {
            reuseAddress = false
            bind(InetSocketAddress(InetAddress.getLoopbackAddress(), 0))
            soTimeout = 5_000
        }
        echoServer = peer
        val peerThread = thread(name = "FirewallDNS-UDP-loopback-peer") {
            try {
                val request = DatagramPacket(ByteArray(MAX_DATAGRAM_BYTES), MAX_DATAGRAM_BYTES)
                peer.receive(request)
                val body = request.data.copyOfRange(request.offset, request.offset + request.length)
                val response = ECHO_PREFIX + body
                peer.send(DatagramPacket(response, response.size, request.socketAddress))
            } catch (_: Throwable) {
                // A missing response is reported by the probe thread.
            }
        }

        val established = Builder()
            .setSession("FirewallDNS UDP TUN diagnostic")
            .setMtu(TUN_MTU)
            .addAddress(TUN_ADDRESS, 32)
            .addRoute(TEST_DESTINATION, 32)
            .establish() ?: throw IllegalStateException("vpn_establish_returned_null")
        descriptor = established
        val output = FileOutputStream(established.fileDescriptor)
        val manager = AndroidUdpFlowManager(
            socketFactory = AndroidProtectedUdpSocketFactory(AndroidDnsSocketProtector(this)),
            maxFlows = 4,
            maxQueuedDatagramsPerFlow = 8,
            maxDatagramBytes = MAX_DATAGRAM_BYTES,
            maxQueuedBytesPerFlow = 16 * 1024,
            receivePollTimeoutMillis = 50,
        )
        val packetBridge = AndroidUdpTunBridge(
            flowManager = manager,
            writeTunPacket = { packet ->
                if (running.get()) synchronized(writeLock) {
                    if (running.get()) {
                        output.write(packet)
                        output.flush()
                        responsesOut.incrementAndGet()
                    }
                }
            },
            mapRemoteEndpoint = {
                InetSocketAddress(InetAddress.getLoopbackAddress(), peer.localPort)
            },
        )
        bridge = packetBridge
        running.set(true)
        val readerReady = CountDownLatch(1)
        reader = thread(name = "FirewallDNS-UDP-TUN-reader") {
            try {
                FileInputStream(established.fileDescriptor).use { input ->
                    val buffer = ByteArray(MAX_PACKET_BYTES)
                    readerReady.countDown()
                    while (running.get()) {
                        val length = input.read(buffer)
                        if (length < 0) break
                        if (length == 0) continue
                        packetsIn.incrementAndGet()
                        when (packetBridge.process(buffer.copyOf(length))) {
                            UdpTunPacketResult.QUEUED -> Unit
                            UdpTunPacketResult.DNS_BYPASS, UdpTunPacketResult.UNSUPPORTED -> unsupported.incrementAndGet()
                            UdpTunPacketResult.REJECTED -> rejected.incrementAndGet()
                        }
                    }
                }
            } catch (_: Throwable) {
                // Closing the descriptor releases the blocking TUN read.
            }
        }

        thread(name = "FirewallDNS-UDP-TUN-probe") {
            var success = false
            var responseText: String? = null
            var failureStage = "reader_ready"
            try {
                check(readerReady.await(2, TimeUnit.SECONDS)) { "tun_reader_not_ready" }
                failureStage = "send_udp_into_tun"
                DatagramSocket().use { client ->
                    client.soTimeout = 4_000
                    val payload = PROBE_PAYLOAD
                    val destination = InetAddress.getByName(TEST_DESTINATION)
                    client.send(DatagramPacket(payload, payload.size, destination, TEST_PORT))
                    failureStage = "receive_udp_response_from_tun"
                    val received = DatagramPacket(ByteArray(MAX_DATAGRAM_BYTES), MAX_DATAGRAM_BYTES)
                    client.receive(received)
                    responseText = String(received.data, received.offset, received.length, Charsets.UTF_8)
                    success = responseText == String(ECHO_PREFIX + payload, Charsets.UTF_8)
                    check(success) { "udp_response_payload_mismatch" }
                }
                peerThread.join(1_000)
            } catch (failure: Throwable) {
                failureStage = "$failureStage:${failure.javaClass.simpleName}"
                responseText = failure.message
            } finally {
                publishReport(success, failureStage, responseText)
                stopDiagnostic()
                stopSelf()
            }
        }
    }

    private fun publishReport(success: Boolean, stage: String, detail: String?) {
        val json = """
            {
              "format": "firewalldns-udp-tun-bridge-diagnostic-v1",
              "created_at_utc": "${Instant.now()}",
              "device": {
                "manufacturer": ${json(Build.MANUFACTURER)},
                "model": ${json(Build.MODEL)},
                "android_release": ${json(Build.VERSION.RELEASE)},
                "sdk_int": ${Build.VERSION.SDK_INT}
              },
              "scope": {
                "vpn_active": true,
                "destination": "$TEST_DESTINATION:$TEST_PORT",
                "upstream": "127.0.0.1 loopback echo",
                "public_network_used": false,
                "dns_intercepted": false,
                "production_vpn_modified": false
              },
              "result": {
                "success": $success,
                "stage": ${json(stage)},
                "detail": ${detail?.let(::json) ?: "null"},
                "tun_packets_in": ${packetsIn.get()},
                "tun_responses_out": ${responsesOut.get()},
                "unsupported_or_dns_bypass": ${unsupported.get()},
                "rejected": ${rejected.get()},
                "active_udp_flows": ${bridge?.activeFlowCount ?: 0}
              }
            }
        """.trimIndent()
        sendBroadcast(Intent(ACTION_RESULT).setPackage(packageName).putExtra(EXTRA_REPORT, json))
    }

    private fun publishFailure(stage: String, detail: String) {
        val json = """{"format":"firewalldns-udp-tun-bridge-diagnostic-v1","success":false,"stage":${json(stage)},"detail":${json(detail)},"public_network_used":false}"""
        sendBroadcast(Intent(ACTION_RESULT).setPackage(packageName).putExtra(EXTRA_REPORT, json))
    }

    @Synchronized
    private fun stopDiagnostic() {
        if (!running.getAndSet(false) && descriptor == null && bridge == null) {
            runCatching { echoServer?.close() }
            echoServer = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            return
        }
        val current = descriptor
        descriptor = null
        synchronized(writeLock) {
            runCatching { current?.close() }
        }
        reader?.interrupt()
        reader = null
        runCatching { bridge?.close() }
        bridge = null
        runCatching { echoServer?.close() }
        echoServer = null
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    private fun notification(): Notification {
        val channelId = "firewalldns_udp_tun_diagnostic"
        if (Build.VERSION.SDK_INT >= 26) {
            getSystemService(NotificationManager::class.java).createNotificationChannel(
                NotificationChannel(channelId, "Diagnóstico UDP TUN", NotificationManager.IMPORTANCE_LOW),
            )
        }
        return if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(this, channelId)
                .setContentTitle("FirewallDNS - prueba UDP")
                .setContentText("Prueba local de transporte UDP por TUN")
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setOngoing(true)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("FirewallDNS - prueba UDP")
                .setContentText("Prueba local de transporte UDP por TUN")
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setOngoing(true)
                .build()
        }
    }

    override fun onRevoke() {
        stopDiagnostic()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopDiagnostic()
        super.onDestroy()
    }

    private fun json(value: String): String =
        "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n") + "\""

    companion object {
        const val ACTION_START = "com.firewalldns.diagnostics.UDP_TUN_BRIDGE_START"
        const val ACTION_STOP = "com.firewalldns.diagnostics.UDP_TUN_BRIDGE_STOP"
        const val ACTION_RESULT = "com.firewalldns.diagnostics.UDP_TUN_BRIDGE_RESULT"
        const val EXTRA_REPORT = "report_json"
        private const val NOTIFICATION_ID = 7733
        private const val TUN_ADDRESS = "10.77.0.2"
        private const val TEST_DESTINATION = "198.18.0.1"
        private const val TEST_PORT = 44443
        private const val TUN_MTU = 1500
        private const val MAX_PACKET_BYTES = 65_535
        private const val MAX_DATAGRAM_BYTES = 1_024
        private val PROBE_PAYLOAD = "firewalldns-protected-udp-tun-probe".toByteArray()
        private val ECHO_PREFIX = "firewalldns-echo:".toByteArray()
    }
}
