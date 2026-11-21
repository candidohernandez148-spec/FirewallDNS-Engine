package com.firewalldns.engine.android

import com.firewalldns.engine.dns.DnsExchangeCancellation
import com.firewalldns.engine.dns.DnsTcpSessionProcessor
import com.firewalldns.engine.dns.DnsUpstreamResult
import com.firewalldns.engine.runtime.DnsTcpSessionRegistry
import com.firewalldns.engine.runtime.DnsTcpSessionWorker
import com.firewalldns.engine.runtime.EngineRuntime
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

data class SmoltcpDnsTcpMetrics(
    val packetsAccepted: Long,
    val ingressRejected: Long,
    val sessionsOpened: Long,
    val sessionsClosed: Long,
    val dataEvents: Long,
    val peerHalfCloses: Long,
    val responsesQueued: Long,
    val responseFailures: Long,
    val activeSessions: Int,
    val nativeErrors: Long,
)

/**
 * Bridges the native smoltcp owner to existing DNS policy and protected upstream
 * clients. TUN reader threads may call offerPacket; pollOwner and every other
 * native operation must run on one dedicated owner thread.
 */
class SmoltcpDnsTcpCoordinator(
    private val transport: NativeTcpDnsTransport,
    private val engine: EngineRuntime,
    private val exchangeUpstream: (ByteArray, DnsExchangeCancellation) -> DnsUpstreamResult,
    private val appIdentityResolver: AppIdentityResolver,
    private val onTunPacket: (ByteArray) -> Unit,
    private val wakeOwner: () -> Unit,
    private val maxSessions: Int = 64,
    private val clockMillis: () -> Long = { android.os.SystemClock.elapsedRealtime() },
    private val clockNanos: () -> Long = System::nanoTime,
) : AutoCloseable {
    private val closed = AtomicBoolean(false)
    private val processors = ConcurrentHashMap<Long, DnsTcpSessionProcessor>()
    private val flowBySession = HashMap<Long, NativeTcpDnsEvent.SessionOpened>()
    private val activeSessionIds = LinkedHashSet<Long>()
    private val peerHalfClosed = HashSet<Long>()
    private val gracefulClosing = HashSet<Long>()
    private val ownerLock = Any()
    @Volatile private var ownerThread: Thread? = null

    private val packetsAccepted = AtomicLong()
    private val ingressRejected = AtomicLong()
    private val sessionsOpened = AtomicLong()
    private val sessionsClosed = AtomicLong()
    private val dataEvents = AtomicLong()
    private val peerHalfCloses = AtomicLong()
    private val responsesQueued = AtomicLong()
    private val responseFailures = AtomicLong()
    private val nativeErrors = AtomicLong()

    private val registry = DnsTcpSessionRegistry(
        processorFactory = ::createProcessor,
        cancelUpstream = { sessionId -> processors[sessionId]?.cancelActiveExchange() },
        onResponsesAvailable = { wakeOwnerSafely() },
        maxSessions = maxSessions,
        idleTimeoutNanos = 60_000_000_000L,
        nowNanos = clockNanos,
    )

    /** Safe for the TUN reader: JNI only appends to a separate bounded queue. */
    fun offerPacket(packet: ByteArray, length: Int = packet.size): Int {
        if (closed.get() || length <= 0 || length > packet.size) return ERROR_CLOSED
        val exactPacket = if (length == packet.size) packet else packet.copyOf(length)
        val result = transport.enqueuePacket(exactPacket)
        if (result == NativeTcpDnsTransport.RESULT_OK) {
            packetsAccepted.incrementAndGet()
            wakeOwnerSafely()
        } else {
            ingressRejected.incrementAndGet()
        }
        return result
    }

    /** Called only from the dedicated smoltcp owner thread. */
    fun pollOwner(): SmoltcpDnsTcpMetrics {
        check(!closed.get()) { "smoltcp DNS/TCP coordinator is closed" }
        assertOwnerThread()
        val now = clockMillis()

        for (batch in 0 until POLL_BATCHES_PER_TICK) {
            val result = transport.poll(now, MAX_INGRESS_PER_BATCH)
            if (result < 0) {
                nativeErrors.incrementAndGet()
                break
            }
            drainNativeEvents()
            if (result == 0) break
        }

        drainWorkerResponses()
        val flushResult = transport.poll(now, 0)
        if (flushResult < 0) nativeErrors.incrementAndGet()
        drainNativeEvents()

        for (sessionId in peerHalfClosed.toList()) {
            if (registry.isActive(sessionId) && registry.isIdle(sessionId)) {
                if (transport.closeSession(sessionId, abort = false)) {
                    registry.closeSession(sessionId)
                    gracefulClosing += sessionId
                }
            }
        }
        if (gracefulClosing.isNotEmpty()) {
            val closePoll = transport.poll(now, 0)
            if (closePoll < 0) nativeErrors.incrementAndGet()
            drainNativeEvents()
        }
        drainTunPackets()

        val expired = registry.expireIdleSessions(clockNanos())
        expired.forEach { sessionId ->
            transport.closeSession(sessionId, abort = true)
            cleanupSession(sessionId)
        }

        for (sessionId in activeSessionIds.toList()) {
            if (!gracefulClosing.contains(sessionId) && !registry.isActive(sessionId)) {
                transport.closeSession(sessionId, abort = true)
                cleanupSession(sessionId)
            }
        }

        return metrics()
    }

    fun metrics(): SmoltcpDnsTcpMetrics = SmoltcpDnsTcpMetrics(
        packetsAccepted = packetsAccepted.get(),
        ingressRejected = ingressRejected.get(),
        sessionsOpened = sessionsOpened.get(),
        sessionsClosed = sessionsClosed.get(),
        dataEvents = dataEvents.get(),
        peerHalfCloses = peerHalfCloses.get(),
        responsesQueued = responsesQueued.get(),
        responseFailures = responseFailures.get(),
        activeSessions = registry.activeSessionCount,
        nativeErrors = nativeErrors.get(),
    )

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        registry.close()
        processors.clear()
        flowBySession.clear()
        activeSessionIds.clear()
        peerHalfClosed.clear()
        gracefulClosing.clear()
        transport.close()
    }

    private fun createProcessor(sessionId: Long): DnsTcpSessionProcessor {
        val flow = checkNotNull(flowBySession[sessionId]) {
            "Missing smoltcp flow metadata for session $sessionId"
        }
        val appPackage = appIdentityResolver.resolveAppPackage(
            protocol = IP_PROTOCOL_TCP,
            sourceAddress = flow.clientAddress,
            sourcePort = flow.clientPort,
            destinationAddress = flow.serverAddress,
            destinationPort = flow.serverPort,
        )
        return DnsTcpSessionProcessor(
            evaluateDns = { query, _ -> engine.evaluateDns(query, appPackage) },
            exchangeUpstream = { query, cancellation ->
                exchangeUpstream(query, cancellation)
            },
        ).also { processors[sessionId] = it }
    }

    private fun drainNativeEvents() {
        repeat(MAX_EVENTS_PER_TICK) {
            val event = transport.takeEvent() ?: return
            when (event) {
                is NativeTcpDnsEvent.SessionOpened -> {
                    flowBySession[event.sessionId] = event
                    when (registry.openSession(event.sessionId)) {
                        DnsTcpSessionRegistry.OpenResult.Opened -> {
                            activeSessionIds += event.sessionId
                            sessionsOpened.incrementAndGet()
                        }
                        else -> {
                            transport.closeSession(event.sessionId, abort = true)
                            cleanupSession(event.sessionId)
                        }
                    }
                }
                is NativeTcpDnsEvent.Data -> {
                    dataEvents.incrementAndGet()
                    when (val result = registry.offer(event.sessionId, event.bytes)) {
                        DnsTcpSessionRegistry.OfferResult.MissingSession -> {
                            transport.closeSession(event.sessionId, abort = true)
                            cleanupSession(event.sessionId)
                        }
                        is DnsTcpSessionRegistry.OfferResult.WorkerResult -> {
                            if (result.result != DnsTcpSessionWorker.OfferResult.Accepted) {
                                transport.closeSession(event.sessionId, abort = true)
                                cleanupSession(event.sessionId)
                            }
                        }
                    }
                }
                is NativeTcpDnsEvent.PeerHalfClosed -> {
                    peerHalfClosed += event.sessionId
                    peerHalfCloses.incrementAndGet()
                }
                is NativeTcpDnsEvent.SessionClosed -> {
                    registry.closeSession(event.sessionId)
                    cleanupSession(event.sessionId)
                    sessionsClosed.incrementAndGet()
                }
            }
        }
    }

    private fun drainWorkerResponses() {
        for (sessionId in activeSessionIds.toList()) {
            val frames = registry.drainResponses(sessionId)
            var failed = false
            for (frame in frames) {
                if (transport.queueResponse(sessionId, frame) != NativeTcpDnsTransport.RESULT_OK) {
                    responseFailures.incrementAndGet()
                    failed = true
                    break
                }
                responsesQueued.incrementAndGet()
            }
            if (failed) {
                registry.closeSession(sessionId)
                transport.closeSession(sessionId, abort = true)
                cleanupSession(sessionId)
            } else if (!gracefulClosing.contains(sessionId) && !registry.isActive(sessionId)) {
                transport.closeSession(sessionId, abort = true)
                cleanupSession(sessionId)
            }
        }
    }

    private fun drainTunPackets() {
        repeat(MAX_EGRESS_PACKETS_PER_TICK) {
            val packet = transport.takePacket() ?: return
            runCatching { onTunPacket(packet) }.onFailure { nativeErrors.incrementAndGet() }
        }
    }

    private fun cleanupSession(sessionId: Long) {
        flowBySession.remove(sessionId)
        processors.remove(sessionId)
        activeSessionIds.remove(sessionId)
        peerHalfClosed.remove(sessionId)
        gracefulClosing.remove(sessionId)
    }

    private fun assertOwnerThread() {
        val current = Thread.currentThread()
        synchronized(ownerLock) {
            val existing = ownerThread
            check(existing == null || existing === current) {
                "smoltcp Interface/SocketSet accessed from more than one owner thread"
            }
            if (existing == null) ownerThread = current
        }
    }

    private fun wakeOwnerSafely() {
        runCatching(wakeOwner)
    }

    private companion object {
        const val IP_PROTOCOL_TCP = 6
        const val POLL_BATCHES_PER_TICK = 4
        const val MAX_INGRESS_PER_BATCH = 32
        const val MAX_EVENTS_PER_TICK = 256
        const val MAX_EGRESS_PACKETS_PER_TICK = 256
        const val ERROR_CLOSED = -100
    }
}
