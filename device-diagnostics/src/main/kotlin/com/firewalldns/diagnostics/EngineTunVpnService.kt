package com.firewalldns.diagnostics

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Handler
import android.os.Looper
import com.firewalldns.engine.android.AndroidEngineRuntime
import com.firewalldns.engine.android.TunDnsPacketProcessor
import com.firewalldns.engine.dns.DnsUpstreamConfig
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.InetAddress
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

/**
 * Real DNS-only VPN data path for the standalone diagnostics application.
 * Only the virtual DNS endpoints are routed to this TUN. Arbitrary IP forwarding
 * and client-side DNS-over-TCP are explicitly outside this adapter's scope.
 */
class EngineTunVpnService : VpnService() {
    @Volatile private var tun: ParcelFileDescriptor? = null
    @Volatile private var reader: Thread? = null
    @Volatile private var workers: ThreadPoolExecutor? = null
    @Volatile private var activeRuntime: AndroidEngineRuntime? = null
    @Volatile private var statusPublisher: ScheduledExecutorService? = null
    @Volatile private var serviceState: String = "stopped"
    private val running = AtomicBoolean(false)
    private val packetsIn = AtomicLong()
    private val dnsProcessed = AtomicLong()
    private val dropped = AtomicLong()
    private val responsesOut = AtomicLong()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STATUS_REQUEST) {
            publish(serviceState)
            return START_NOT_STICKY
        }
        if (intent?.action == ACTION_STOP) {
            serviceState = "stopping"
            publish(serviceState)
            stopDataPlane()
            stopSelfResult(startId)
            return START_NOT_STICKY
        }
        if (intent?.action != ACTION_START || running.get()) {
            if (!running.get()) stopSelf(startId)
            return START_NOT_STICKY
        }
        startForeground(NOTIFICATION_ID, notification())
        try {
            val descriptor = Builder()
                .setSession("FirewallDNS Engine - DNS TUN")
                .setMtu(TUN_MTU)
                .addAddress(IPV4_INTERFACE, 32)
                .addDnsServer(InetAddress.getByName(IPV4_DNS))
                .addRoute(IPV4_DNS, 32)
                .addAddress(IPV6_INTERFACE, 128)
                .addDnsServer(InetAddress.getByName(IPV6_DNS))
                .addRoute(IPV6_DNS, 128)
                .establish()
            if (descriptor == null) {
                publish("tun_establish_failed")
                stopSelf(startId)
                return START_NOT_STICKY
            }
            tun = descriptor
            running.set(true)
            serviceState = "starting"
            startDataPlane(descriptor)
            serviceState = "running"
            startStatusPublisher()
            publish(serviceState)
        } catch (failure: Throwable) {
            serviceState = "start_failed:${failure.javaClass.simpleName}"
            publish(serviceState)
            stopDataPlane()
            stopSelfResult(startId)
        }
        return START_NOT_STICKY
    }

    private fun startDataPlane(descriptor: ParcelFileDescriptor) {
        val runtime = AndroidEngineRuntime(this)
        activeRuntime = runtime
        val upstream = runtime.createDnsFailover(
            listOf(
                DnsUpstreamConfig("1.1.1.1", timeoutMillis = 1_800, udpBufferBytes = 4_096),
                DnsUpstreamConfig("8.8.8.8", timeoutMillis = 1_800, udpBufferBytes = 4_096),
                DnsUpstreamConfig("9.9.9.9", timeoutMillis = 1_800, udpBufferBytes = 4_096),
            ),
        )
        val processor = TunDnsPacketProcessor(runtime.engine) { query -> upstream.exchange(query) }
        val pool = ThreadPoolExecutor(
            WORKER_COUNT,
            WORKER_COUNT,
            0L,
            TimeUnit.MILLISECONDS,
            ArrayBlockingQueue(RING_CAPACITY),
            { task -> Thread(task, "firewalldns-engine-tun-worker").apply { isDaemon = true } },
            ThreadPoolExecutor.AbortPolicy(),
        )
        workers = pool

        reader = thread(name = "firewalldns-engine-tun-reader") {
            val output = FileOutputStream(descriptor.fileDescriptor)
            try {
                FileInputStream(descriptor.fileDescriptor).use { input ->
                    val buffer = ByteArray(MAX_PACKET_BYTES)
                    while (running.get()) {
                        val length = input.read(buffer)
                        if (length <= 0) continue
                        packetsIn.incrementAndGet()
                        val packet = buffer.copyOf(length)
                        try {
                            pool.execute {
                                val response = try { processor.process(packet) } catch (_: Throwable) { null }
                                if (response != null && running.get()) {
                                    try {
                                        synchronized(output) {
                                            output.write(response)
                                            output.flush()
                                        }
                                        responsesOut.incrementAndGet()
                                        dnsProcessed.incrementAndGet()
                                    } catch (_: Throwable) {
                                        dropped.incrementAndGet()
                                    }
                                } else {
                                    dropped.incrementAndGet()
                                }
                            }
                        } catch (_: java.util.concurrent.RejectedExecutionException) {
                            dropped.incrementAndGet()
                        }
                    }
                }
            } catch (_: Throwable) {
                // Closing the TUN descriptor releases the blocking read on teardown.
            } finally {
                try { output.close() } catch (_: Throwable) {}
                publish("engine_dns_tun_stopped")
            }
        }
    }

    private fun startStatusPublisher() {
        statusPublisher?.shutdownNow()
        statusPublisher = Executors.newSingleThreadScheduledExecutor { task ->
            Thread(task, "firewalldns-engine-status").apply { isDaemon = true }
        }.also { scheduler ->
            scheduler.scheduleAtFixedRate({ publish(serviceState) }, 0, STATUS_INTERVAL_MS, TimeUnit.MILLISECONDS)
        }
    }

    private fun publish(state: String) {
        val metrics = activeRuntime?.engine?.metrics()
        sendBroadcast(
            Intent(ACTION_STATUS).setPackage(packageName)
                .putExtra(EXTRA_STATE, state)
                .putExtra("packets_in", packetsIn.get())
                .putExtra("dns_processed", dnsProcessed.get())
                .putExtra("responses_out", responsesOut.get())
                .putExtra("dropped", dropped.get())
                .putExtra("blocked", metrics?.blocked ?: 0L)
                .putExtra("observed", metrics?.observed ?: 0L)
                .putExtra("allowed", metrics?.allowed ?: 0L)
                .putExtra("rejected", metrics?.rejected ?: 0L)
                .putExtra("updated_at_elapsed_ms", android.os.SystemClock.elapsedRealtime()),
        )
    }

    private fun notification(): Notification {
        val channelId = "firewalldns_engine_dns_tun"
        if (Build.VERSION.SDK_INT >= 26) {
            getSystemService(NotificationManager::class.java).createNotificationChannel(
                NotificationChannel(channelId, "FirewallDNS Engine", NotificationManager.IMPORTANCE_LOW),
            )
        }
        return if (Build.VERSION.SDK_INT >= 26) {
            Notification.Builder(this, channelId)
                .setContentTitle("FirewallDNS Engine")
                .setContentText("Procesando DNS mediante el motor propio")
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setOngoing(true)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("FirewallDNS Engine")
                .setContentText("Procesando DNS mediante el motor propio")
                .setSmallIcon(android.R.drawable.stat_sys_warning)
                .setOngoing(true)
                .build()
        }
    }

    override fun onRevoke() {
        stopDataPlane()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopDataPlane()
        super.onDestroy()
    }

    @Synchronized
    private fun stopDataPlane() {
        if (!running.getAndSet(false) && tun == null && workers == null) {
            statusPublisher?.shutdownNow()
            statusPublisher = null
            stopForeground(STOP_FOREGROUND_REMOVE)
            return
        }
        statusPublisher?.shutdownNow()
        statusPublisher = null
        // Closing the descriptor is what unblocks the TUN reader; interrupt alone is insufficient.
        val descriptor = tun
        tun = null
        try { descriptor?.close() } catch (_: Throwable) {}
        reader?.interrupt()
        reader = null
        workers?.shutdownNow()
        workers = null
        activeRuntime = null
        serviceState = "stopped"
        publish(serviceState)
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    companion object {
        const val ACTION_START = "com.firewalldns.diagnostics.ENGINE_TUN_START"
        const val ACTION_STOP = "com.firewalldns.diagnostics.ENGINE_TUN_STOP"
        const val ACTION_STATUS = "com.firewalldns.diagnostics.ENGINE_TUN_STATUS"
        const val ACTION_STATUS_REQUEST = "com.firewalldns.diagnostics.ENGINE_TUN_STATUS_REQUEST"
        const val EXTRA_STATE = "state"
        private const val IPV4_INTERFACE = "10.77.0.2"
        private const val IPV4_DNS = "10.77.0.1"
        private const val IPV6_INTERFACE = "fd77::2"
        private const val IPV6_DNS = "fd77::1"
        private const val NOTIFICATION_ID = 7732
        private const val TUN_MTU = 1500
        private const val MAX_PACKET_BYTES = 65_535
        private const val WORKER_COUNT = 4
        private const val RING_CAPACITY = 256
        private const val STATUS_INTERVAL_MS = 500L
    }
}
