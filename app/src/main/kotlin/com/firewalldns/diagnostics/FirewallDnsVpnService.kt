package com.firewalldns.diagnostics

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import com.firewalldns.engine.android.AndroidAppIdentityResolver
import com.firewalldns.engine.android.AndroidEngineRuntime
import com.firewalldns.engine.android.TunDataPlaneCoordinator
import com.firewalldns.engine.android.TunDataPlaneMetrics
import com.firewalldns.engine.android.TunDataPlaneSecurityConfig
import com.firewalldns.engine.android.TunDataPlaneValidationResult
import com.firewalldns.engine.dns.DnsUpstreamConfig
import org.json.JSONArray
import org.json.JSONObject
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

/**
 * Production VPN data-plane service gated by preflight validation of:
 * 1. [VpnService.protect] for UDP and TCP upstream sockets.
 * 2. Loop-free routing and own-application exclusion.
 * 3. Zero-DNS-leak dual-stack interception and DoT (853) sinkholing.
 */
class FirewallDnsVpnService : VpnService() {
    private val running = AtomicBoolean(false)
    @Volatile
    private var tunInterface: ParcelFileDescriptor? = null
    @Volatile
    private var tickThread: Thread? = null
    @Volatile
    private var statusThread: Thread? = null
    private val diagnosticMetrics = FirewallDnsDiagnosticMetrics()

    private val packetsIn = AtomicLong()
    private val responsesOut = AtomicLong()
    private val queueRejected = AtomicLong()
    private val responseWriteFailed = AtomicLong()
    private val stoppedBeforeResponse = AtomicLong()
    private val processorFailed = AtomicLong()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopProductionVpn()
                return START_NOT_STICKY
            }
            ACTION_START -> startProductionVpn()
        }
        return START_NOT_STICKY
    }

    private fun startProductionVpn() {
        if (!running.compareAndSet(false, true)) return
        startForegroundCompat("FirewallDNS Producción activo")
        broadcastState(state = "validating")

        val upstreams = listOf(
            DnsUpstreamConfig("1.1.1.1", 53, 1_500),
            DnsUpstreamConfig("8.8.8.8", 53, 1_500),
        )
        val ipv4Routes = TunDataPlaneSecurityConfig.DEFAULT_INTERCEPTED_IPV4_ROUTES
        val ipv6Routes = TunDataPlaneSecurityConfig.DEFAULT_INTERCEPTED_IPV6_ROUTES

        val builder = Builder()
            .setSession("FirewallDNS Production Data Plane")
            .setMtu(1500)
            .setBlocking(true)
            .addAddress(TunDataPlaneSecurityConfig.DEFAULT_TUN_IPV4_ADDRESS, 32)
            .addDnsServer(TunDataPlaneSecurityConfig.DEFAULT_TUN_IPV4_DNS)
            .addAddress(TunDataPlaneSecurityConfig.DEFAULT_TUN_IPV6_ADDRESS, 128)
            .addDnsServer(TunDataPlaneSecurityConfig.DEFAULT_TUN_IPV6_DNS)

        ipv4Routes.forEach { cidr ->
            val (ip, prefix) = cidr.split('/')
            builder.addRoute(ip, prefix.toInt())
        }
        ipv6Routes.forEach { cidr ->
            val (ip, prefix) = cidr.split('/')
            builder.addRoute(ip, prefix.toInt())
        }

        val selfExcluded = runCatching {
            builder.addDisallowedApplication(packageName)
            true
        }.getOrDefault(false)

        val pfd = builder.establish()
        if (pfd == null) {
            running.set(false)
            broadcastState(state = "stopped")
            if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            return
        }
        tunInterface = pfd
        diagnosticMetrics.reset()
        packetsIn.set(0)
        responsesOut.set(0)
        queueRejected.set(0)
        responseWriteFailed.set(0)
        stoppedBeforeResponse.set(0)
        processorFailed.set(0)

        val runtime = AndroidEngineRuntime(this)
        val securityConfig = TunDataPlaneSecurityConfig(
            upstreamConfigs = upstreams,
            interceptedRoutesIpv4 = ipv4Routes,
            interceptedRoutesIpv6 = ipv6Routes,
            appPackageName = packageName,
            disallowedPackages = if (selfExcluded) setOf(packageName) else emptySet(),
            allowBypass = false,
            blockExternalDotPort853 = true,
            allowLoopbackUpstreamsForTesting = false,
        )

        val coordinator = when (
            val activation = TunDataPlaneCoordinator.createValidated(
                engine = runtime.engine,
                rawProtector = runtime.socketProtector,
                securityConfig = securityConfig,
                appIdentityResolver = AndroidAppIdentityResolver(this),
            )
        ) {
            is TunDataPlaneCoordinator.ActivationResult.Activated -> activation.coordinator
            is TunDataPlaneCoordinator.ActivationResult.Rejected -> {
                running.set(false)
                runCatching { pfd.close() }
                tunInterface = null
                broadcastState(
                    state = "activation_rejected",
                    runtime = runtime,
                    validation = activation.validation,
                )
                if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
                return
            }
        }

        val input = FileInputStream(pfd.fileDescriptor)
        val output = FileOutputStream(pfd.fileDescriptor)
        val writeLock = Any()

        val workers = ThreadPoolExecutor(
            4,
            8,
            15L,
            TimeUnit.SECONDS,
            ArrayBlockingQueue(256),
        )

        fun writePacketToTun(packetBytes: ByteArray) {
            if (!running.get()) {
                stoppedBeforeResponse.incrementAndGet()
                return
            }
            synchronized(writeLock) {
                runCatching {
                    output.write(packetBytes)
                    responsesOut.incrementAndGet()
                }.onFailure {
                    responseWriteFailed.incrementAndGet()
                }
            }
        }

        val tick = thread(name = "firewalldns-prod-tick") {
            while (running.get()) {
                runCatching {
                    val timerPackets = coordinator.tick()
                    for (pkt in timerPackets) {
                        writePacketToTun(pkt)
                    }
                }
                try {
                    Thread.sleep(50)
                } catch (_: InterruptedException) {
                    break
                }
            }
        }
        tickThread = tick

        val status = thread(name = "firewalldns-prod-status") {
            while (running.get()) {
                broadcastState(
                    state = "running",
                    runtime = runtime,
                    validation = coordinator.validation,
                    dataPlaneMetrics = coordinator.metrics(),
                )
                try {
                    Thread.sleep(500)
                } catch (_: InterruptedException) {
                    break
                }
            }
        }
        statusThread = status

        thread(name = "firewalldns-prod-tun-reader") {
            val buffer = ByteArray(4096)
            try {
                while (running.get()) {
                    val read = input.read(buffer)
                    if (read <= 0) continue
                    val packet = buffer.copyOf(read)
                    packetsIn.incrementAndGet()
                    diagnosticMetrics.record(packet, read)
                    try {
                        workers.execute {
                            if (!running.get()) {
                                stoppedBeforeResponse.incrementAndGet()
                                return@execute
                            }
                            try {
                                when (val result = coordinator.onPacket(packet, read)) {
                                    is TunDataPlaneCoordinator.PacketHandlingResult.Responses -> {
                                        diagnosticMetrics.recordProcessingOutcome(result.outcome)
                                        for (out in result.packets) {
                                            writePacketToTun(out)
                                        }
                                    }
                                    is TunDataPlaneCoordinator.PacketHandlingResult.Consumed -> {
                                        diagnosticMetrics.recordProcessingOutcome(result.outcome)
                                    }
                                    is TunDataPlaneCoordinator.PacketHandlingResult.BlockedOrDropped -> {
                                        diagnosticMetrics.recordProcessingOutcome(result.outcome)
                                        for (out in result.responsePackets) {
                                            writePacketToTun(out)
                                        }
                                    }
                                }
                            } catch (_: Throwable) {
                                processorFailed.incrementAndGet()
                            }
                        }
                    } catch (_: Throwable) {
                        queueRejected.incrementAndGet()
                    }
                }
            } catch (_: Throwable) {
                // Descriptor closed on stop
            } finally {
                running.set(false)
                tick.interrupt()
                status.interrupt()
                if (tickThread === tick) tickThread = null
                if (statusThread === status) statusThread = null
                coordinator.close()
                workers.shutdownNow()
                runCatching { pfd.close() }
                if (tunInterface === pfd) tunInterface = null
                broadcastState(
                    state = "stopped",
                    runtime = runtime,
                    validation = coordinator.validation,
                    dataPlaneMetrics = coordinator.metrics(),
                )
                if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    override fun onRevoke() {
        stopProductionVpn()
        super.onRevoke()
    }

    private fun stopProductionVpn() {
        val wasRunning = running.getAndSet(false)
        val pfd = tunInterface
        tunInterface = null
        tickThread?.interrupt()
        statusThread?.interrupt()
        tickThread = null
        statusThread = null
        if (!wasRunning && pfd == null) return
        broadcastState("stopping")
        runCatching { pfd?.close() }
        broadcastState("stopped")
        if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun broadcastState(
        state: String,
        runtime: AndroidEngineRuntime? = null,
        validation: TunDataPlaneValidationResult? = null,
        dataPlaneMetrics: TunDataPlaneMetrics? = null,
    ) {
        val m = runtime?.engine?.metrics()
        val valJson = if (validation != null) {
            JSONObject().apply {
                put("passed", validation.passed)
                put("protect_verified", validation.protectVerified)
                put("loop_free_verified", validation.loopFreeVerified)
                put("zero_dns_leaks_verified", validation.zeroDnsLeaksVerified)
                put("failure_reasons", JSONArray(validation.failureReasons))
            }.toString()
        } else {
            "{}"
        }
        val intent = Intent(ACTION_STATUS).apply {
            setPackage(packageName)
            putExtra(EXTRA_STATE, state)
            putExtra("packets_in", packetsIn.get())
            putExtra("responses_out", responsesOut.get())
            putExtra("queue_rejected", queueRejected.get())
            putExtra("response_write_failed", responseWriteFailed.get())
            putExtra("stopped_before_response", stoppedBeforeResponse.get())
            putExtra("processor_failed", processorFailed.get())
            putExtra("blocked", m?.blocked ?: 0L)
            putExtra("observed", m?.observed ?: 0L)
            putExtra("allowed", m?.allowed ?: 0L)
            putExtra("rejected", m?.rejected ?: 0L)
            putExtra("validation_json", valJson)
            putExtra("protect_verified", validation?.protectVerified ?: false)
            putExtra("loop_free_verified", validation?.loopFreeVerified ?: false)
            putExtra("zero_dns_leaks_verified", validation?.zeroDnsLeaksVerified ?: false)
            putExtra("loops_blocked", dataPlaneMetrics?.loopsBlocked ?: 0L)
            putExtra("dns_leaks_blocked", dataPlaneMetrics?.dnsLeaksBlocked ?: 0L)
            putExtra("protect_fail_closed", dataPlaneMetrics?.runtimeProtectFailClosedBlocked ?: 0L)
            putExtra("protect_udp_successes", dataPlaneMetrics?.socketProtection?.udpSuccesses ?: 0L)
            putExtra("protect_tcp_successes", dataPlaneMetrics?.socketProtection?.tcpSuccesses ?: 0L)
            putExtra("protect_failures", dataPlaneMetrics?.socketProtection?.totalFailures ?: 0L)
            putExtra("fragments_reassembled", dataPlaneMetrics?.fragmentReassembly?.packetsReassembled ?: 0L)
            putExtra("dns_tcp_sessions_active", dataPlaneMetrics?.tcpStack?.activeSessions ?: 0)
            putExtra("dns_tcp_queries_processed", dataPlaneMetrics?.tcpStack?.dnsQueriesProcessed ?: 0L)
            putExtra("dns_tcp_retransmissions", dataPlaneMetrics?.tcpStack?.retransmissions ?: 0L)
            putExtra("active_flows", dataPlaneMetrics?.flows?.activeFlows ?: 0)
            putExtra("flows_opened", dataPlaneMetrics?.flows?.totalOpened ?: 0L)
            putExtra("app_identity_resolved", dataPlaneMetrics?.appIdentity?.resolved ?: 0L)
            putExtra("app_identity_degraded", dataPlaneMetrics?.appIdentity?.degradedUnavailable ?: 0L)
            putExtra("updated_at_elapsed_ms", SystemClock.elapsedRealtime())
            putExtra("traffic_classification", diagnosticMetrics.snapshotJson())
        }
        runCatching { sendBroadcast(intent) }
    }

    private fun startForegroundCompat(title: String) {
        val channelId = "firewalldns_prod_tun"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            nm?.createNotificationChannel(
                NotificationChannel(channelId, "FirewallDNS Producción", NotificationManager.IMPORTANCE_LOW),
            )
            val notification = Notification.Builder(this, channelId)
                .setContentTitle(title)
                .setSmallIcon(android.R.drawable.ic_lock_lock)
                .build()
            startForeground(104, notification)
        }
    }

    override fun onDestroy() {
        stopProductionVpn()
        super.onDestroy()
    }

    companion object {
        const val ACTION_START = "com.firewalldns.diagnostics.PROD_VPN_START"
        const val ACTION_STOP = "com.firewalldns.diagnostics.PROD_VPN_STOP"
        const val ACTION_STATUS = "com.firewalldns.diagnostics.PROD_VPN_STATUS"
        const val EXTRA_STATE = "state"
    }
}
