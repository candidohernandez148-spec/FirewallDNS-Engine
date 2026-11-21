package com.firewalldns.diagnostics

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import com.firewalldns.engine.android.AndroidEngineRuntime
import com.firewalldns.engine.android.IpFragmentReassembler
import com.firewalldns.engine.android.TcpStackMetrics
import com.firewalldns.engine.android.TunDnsPacketProcessor
import com.firewalldns.engine.android.TunTcpStack
import com.firewalldns.engine.dns.DnsUpstreamConfig
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.ArrayBlockingQueue
import java.util.concurrent.ThreadPoolExecutor
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong
import kotlin.concurrent.thread

class EngineTunVpnService : VpnService() {
    private val running = AtomicBoolean(false)
    @Volatile
    private var tunInterface: ParcelFileDescriptor? = null
    @Volatile
    private var tickThread: Thread? = null
    @Volatile
    private var statusThread: Thread? = null
    private val diagnosticMetrics = FirewallDnsDiagnosticMetrics()

    private val packetsIn = AtomicLong()
    private val dnsProcessed = AtomicLong()
    private val responsesOut = AtomicLong()
    private val processorReturned = AtomicLong()
    private val processorNoResponse = AtomicLong()
    private val processorFailed = AtomicLong()
    private val queueRejected = AtomicLong()
    private val responseWriteFailed = AtomicLong()
    private val stoppedBeforeResponse = AtomicLong()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopEngineTun()
                return START_NOT_STICKY
            }
            ACTION_START -> startEngineTun()
        }
        return START_NOT_STICKY
    }

    private fun startEngineTun() {
        if (!running.compareAndSet(false, true)) return
        startForegroundCompat("FirewallDNS Engine TUN activo")
        broadcastStatus("starting")

        val builder = Builder()
            .setSession("FirewallDNS Diagnostic TUN")
            .setMtu(1500)
            .addAddress("10.77.0.2", 32)
            .addRoute("10.77.0.1", 32)
            .addDnsServer("10.77.0.1")
            .addAddress("fd77::2", 128)
            .addRoute("fd77::1", 128)
            .addDnsServer("fd77::1")

        val pfd = builder.establish()
        if (pfd == null) {
            running.set(false)
            broadcastStatus("stopped")
            stopSelf()
            return
        }
        tunInterface = pfd
        diagnosticMetrics.reset()
        packetsIn.set(0)
        dnsProcessed.set(0)
        responsesOut.set(0)
        processorReturned.set(0)
        processorNoResponse.set(0)
        processorFailed.set(0)
        queueRejected.set(0)
        responseWriteFailed.set(0)
        stoppedBeforeResponse.set(0)

        val runtime = AndroidEngineRuntime(this)
        val failover = runtime.createDnsFailover(
            listOf(
                DnsUpstreamConfig("1.1.1.1", 53, 1_500),
                DnsUpstreamConfig("8.8.8.8", 53, 1_500),
            ),
        )
        val fragmentReassembler = IpFragmentReassembler()
        val processor = TunDnsPacketProcessor(runtime.engine) { query -> failover.exchange(query) }
        val tcpStack = TunTcpStack(
            engine = runtime.engine,
            exchangeUpstream = { query, cancellation -> failover.exchange(query, cancellation) },
        )
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

        val tick = thread(name = "firewalldns-tun-tcp-tick") {
            while (running.get()) {
                runCatching {
                    fragmentReassembler.evictExpired()
                    val timerPackets = tcpStack.tick()
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

        val status = thread(name = "firewalldns-tun-status") {
            while (running.get()) {
                broadcastStatus("running", runtime, tcpStack.metrics())
                try {
                    Thread.sleep(500)
                } catch (_: InterruptedException) {
                    break
                }
            }
        }
        statusThread = status

        thread(name = "firewalldns-tun-reader") {
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
                                val readyPacket: ByteArray
                                val readyLen: Int
                                when (val frag = fragmentReassembler.process(packet, read)) {
                                    is IpFragmentReassembler.Result.Pending -> {
                                        diagnosticMetrics.recordProcessingOutcome("ip_fragment_buffered_pending")
                                        return@execute
                                    }
                                    is IpFragmentReassembler.Result.Dropped -> {
                                        processorNoResponse.incrementAndGet()
                                        diagnosticMetrics.recordProcessingOutcome(frag.reason)
                                        return@execute
                                    }
                                    is IpFragmentReassembler.Result.Ready -> {
                                        readyPacket = frag.packet
                                        readyLen = frag.length
                                    }
                                }
                                if (isTcpPacket(readyPacket, readyLen)) {
                                    val tcpResponses = tcpStack.onPacket(readyPacket, readyLen)
                                    if (tcpResponses.isEmpty()) {
                                        diagnosticMetrics.recordProcessingOutcome("dns_tcp_segment_consumed")
                                    } else {
                                        for (tcpOut in tcpResponses) {
                                            processorReturned.incrementAndGet()
                                            dnsProcessed.incrementAndGet()
                                            diagnosticMetrics.recordProcessingOutcome("dns_tcp_segment_out")
                                            writePacketToTun(tcpOut)
                                        }
                                    }
                                } else {
                                    when (val result = processor.processDetailed(readyPacket, readyLen)) {
                                        is TunDnsPacketProcessor.PacketResult.Response -> {
                                            processorReturned.incrementAndGet()
                                            dnsProcessed.incrementAndGet()
                                            diagnosticMetrics.recordProcessingOutcome(result.outcome)
                                            writePacketToTun(result.packet)
                                        }
                                        is TunDnsPacketProcessor.PacketResult.NoResponse -> {
                                            processorNoResponse.incrementAndGet()
                                            diagnosticMetrics.recordProcessingOutcome(result.reason)
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
                tcpStack.close()
                fragmentReassembler.clear()
                workers.shutdownNow()
                runCatching { pfd.close() }
                if (tunInterface === pfd) tunInterface = null
                broadcastStatus("stopped", runtime, tcpStack.metrics())
                if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private fun isTcpPacket(packet: ByteArray, length: Int): Boolean {
        if (length < 20) return false
        return when ((packet[0].toInt() ushr 4) and 0x0f) {
            4 -> (packet[9].toInt() and 0xff) == 6
            6 -> {
                if (length < 40) return false
                var next = packet[6].toInt() and 0xff
                var offset = 40
                val payloadLen = ((packet[4].toInt() and 0xff) shl 8) or (packet[5].toInt() and 0xff)
                val end = (40 + payloadLen).coerceAtMost(length)
                var extensions = 0
                val extHeaders = setOf(0, 43, 44, 51, 60)
                while (next in extHeaders) {
                    if (++extensions > 8 || offset + 2 > end) return false
                    if (next == 44) {
                        if (offset + 8 > end) return false
                        next = packet[offset].toInt() and 0xff
                        offset += 8
                        continue
                    }
                    val following = packet[offset].toInt() and 0xff
                    val extLen = if (next == 51) ((packet[offset + 1].toInt() and 0xff) + 2) * 4
                    else ((packet[offset + 1].toInt() and 0xff) + 1) * 8
                    if (extLen < 8 || offset + extLen > end) return false
                    next = following
                    offset += extLen
                }
                next == 6
            }
            else -> false
        }
    }

    override fun onRevoke() {
        stopEngineTun()
        super.onRevoke()
    }

    private fun stopEngineTun() {
        val wasRunning = running.getAndSet(false)
        val pfd = tunInterface
        tunInterface = null
        tickThread?.interrupt()
        statusThread?.interrupt()
        tickThread = null
        statusThread = null
        if (!wasRunning && pfd == null) return
        broadcastStatus("stopping")
        runCatching { pfd?.close() }
        broadcastStatus("stopped")
        if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun broadcastStatus(
        state: String,
        runtime: AndroidEngineRuntime? = null,
        tcpMetrics: TcpStackMetrics? = null,
    ) {
        val m = runtime?.engine?.metrics()
        val dropped = processorNoResponse.get() + processorFailed.get() +
            queueRejected.get() + responseWriteFailed.get() + stoppedBeforeResponse.get()
        val intent = Intent(ACTION_STATUS).apply {
            setPackage(packageName)
            putExtra(EXTRA_STATE, state)
            putExtra("packets_in", packetsIn.get())
            putExtra("dns_processed", dnsProcessed.get())
            putExtra("responses_out", responsesOut.get())
            putExtra("dropped", dropped)
            putExtra("processor_returned_response", processorReturned.get())
            putExtra("processor_no_response", processorNoResponse.get())
            putExtra("processor_failed", processorFailed.get())
            putExtra("queue_rejected", queueRejected.get())
            putExtra("response_write_failed", responseWriteFailed.get())
            putExtra("stopped_before_response", stoppedBeforeResponse.get())
            putExtra("blocked", m?.blocked ?: 0L)
            putExtra("observed", m?.observed ?: 0L)
            putExtra("allowed", m?.allowed ?: 0L)
            putExtra("rejected", m?.rejected ?: 0L)
            putExtra("dns_tcp_sessions_active", tcpMetrics?.activeSessions ?: 0)
            putExtra("dns_tcp_accepted", tcpMetrics?.totalAccepted ?: 0L)
            putExtra("dns_tcp_queries_processed", tcpMetrics?.dnsQueriesProcessed ?: 0L)
            putExtra("dns_tcp_retransmissions", tcpMetrics?.retransmissions ?: 0L)
            putExtra("dns_tcp_fast_retransmissions", tcpMetrics?.fastRetransmissions ?: 0L)
            putExtra("dns_tcp_zero_window_events", tcpMetrics?.zeroWindowEvents ?: 0L)
            putExtra("dns_tcp_closed_gracefully", tcpMetrics?.totalClosedGracefully ?: 0L)
            putExtra("dns_tcp_resets", tcpMetrics?.totalReset ?: 0L)
            putExtra("dns_tcp_rejected_limit", tcpMetrics?.sessionsRejectedLimit ?: 0L)
            putExtra("updated_at_elapsed_ms", SystemClock.elapsedRealtime())
            putExtra("traffic_classification", diagnosticMetrics.snapshotJson())
        }
        runCatching { sendBroadcast(intent) }
    }

    private fun startForegroundCompat(title: String) {
        val channelId = "firewalldns_diag_tun"
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(NotificationManager::class.java)
            nm?.createNotificationChannel(
                NotificationChannel(channelId, "FirewallDNS Diagnostics", NotificationManager.IMPORTANCE_LOW),
            )
            val notification = Notification.Builder(this, channelId)
                .setContentTitle(title)
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .build()
            startForeground(101, notification)
        }
    }

    override fun onDestroy() {
        stopEngineTun()
        super.onDestroy()
    }

    companion object {
        const val ACTION_START = "com.firewalldns.diagnostics.ENGINE_TUN_START"
        const val ACTION_STOP = "com.firewalldns.diagnostics.ENGINE_TUN_STOP"
        const val ACTION_STATUS = "com.firewalldns.diagnostics.ENGINE_TUN_STATUS"
        const val EXTRA_STATE = "state"
    }
}
