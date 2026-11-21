package com.firewalldns.engine.android

import com.firewalldns.engine.dns.DnsExchangeCancellation
import com.firewalldns.engine.dns.DnsTcpSessionProcessor
import com.firewalldns.engine.dns.DnsUpstreamResult
import com.firewalldns.engine.runtime.EngineRuntime
import java.util.TreeMap
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock
import kotlin.random.Random

data class TunTcpStackConfig(
    val targetPort: Int = 53,
    val maxSessions: Int = 64,
    val localMssIpv4: Int = 1460,
    val localMssIpv6: Int = 1440,
    val decoderBufferBytes: Int = DnsTcpSessionProcessor.DEFAULT_DECODER_BUFFER_BYTES,
    val maxFramesPerBatch: Int = DnsTcpSessionProcessor.DEFAULT_MAX_FRAMES_PER_BATCH,
    val maxPendingOutboundBytes: Int = DnsTcpSessionProcessor.DEFAULT_MAX_PENDING_OUTBOUND_BYTES,
    val maxUnackedSegmentsPerSession: Int = 64,
    val maxBufferedOutOfOrderBytes: Int = 8_192,
    val initialRtoMillis: Long = 200L,
    val maxRtoMillis: Long = 3_200L,
    val maxRetransmissions: Int = 5,
    val idleTimeoutMillis: Long = 30_000L,
    val timeWaitMillis: Long = 2_000L,
) {
    init {
        require(targetPort in 1..65_535)
        require(maxSessions in 1..4096)
        require(localMssIpv4 in 536..65_495)
        require(localMssIpv6 in 536..65_475)
        require(maxUnackedSegmentsPerSession in 4..512)
        require(maxBufferedOutOfOrderBytes >= 0)
        require(initialRtoMillis > 0 && maxRtoMillis >= initialRtoMillis)
        require(maxRetransmissions in 1..15)
        require(idleTimeoutMillis > 0 && timeWaitMillis >= 0)
    }
}

data class TcpStackMetrics(
    val activeSessions: Int,
    val totalAccepted: Long,
    val totalClosedGracefully: Long,
    val totalReset: Long,
    val sessionsRejectedLimit: Long,
    val retransmissions: Long,
    val fastRetransmissions: Long,
    val zeroWindowEvents: Long,
    val duplicateBytesDropped: Long,
    val outOfOrderBuffered: Long,
    val outOfOrderDropped: Long,
    val badChecksumDropped: Long,
    val nonTargetPortDropped: Long,
    val dnsQueriesProcessed: Long,
)

/**
 * Bounded per-session TCP socket state machine bridging TUN TCP/53 segments to
 * [DnsTcpSessionProcessor] with sliding window control, RTO retransmissions,
 * fast retransmit, out-of-order reassembly, and graceful FIN / RST lifecycle.
 */
class TunTcpStack(
    private val engine: EngineRuntime,
    private val exchangeUpstream: (ByteArray, DnsExchangeCancellation) -> DnsUpstreamResult,
    private val config: TunTcpStackConfig = TunTcpStackConfig(),
    private val clockNanos: () -> Long = System::nanoTime,
    private val isnProvider: () -> Long = { Random.nextLong(1L, 0xFFFF_FFFFL) },
    private val appIdentityResolver: AppIdentityResolver = NoopAppIdentityResolver,
    private val flowTracker: TunFlowTracker? = null,
) {
    private enum class TcpState {
        SYN_RECEIVED,
        ESTABLISHED,
        CLOSE_WAIT,
        LAST_ACK,
        TIME_WAIT,
        CLOSED,
    }

    private data class TcpFourTuple(
        val ipv6: Boolean,
        val clientAddress: ByteArray,
        val clientPort: Int,
        val serverAddress: ByteArray,
        val serverPort: Int,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is TcpFourTuple) return false
            return ipv6 == other.ipv6 &&
                clientPort == other.clientPort &&
                serverPort == other.serverPort &&
                clientAddress.contentEquals(other.clientAddress) &&
                serverAddress.contentEquals(other.serverAddress)
        }

        override fun hashCode(): Int {
            var result = ipv6.hashCode()
            result = 31 * result + clientAddress.contentHashCode()
            result = 31 * result + clientPort
            result = 31 * result + serverAddress.contentHashCode()
            result = 31 * result + serverPort
            return result
        }
    }

    private class SentSegment(
        var seqStart: Long,
        var seqLen: Int,
        val flags: Int,
        var payload: ByteArray,
        val mssOption: Int?,
        val firstSentNanos: Long,
        var lastSentNanos: Long,
        var retransmitCount: Int = 0,
    )

    private class OutOfOrderSegment(
        val seq: Long,
        val payload: ByteArray,
        val isFin: Boolean,
    )

    private inner class TcpSession(
        val key: TcpFourTuple,
        val processor: DnsTcpSessionProcessor,
        val appPackage: String?,
        serverIsn: Long,
        clientIsn: Long,
        var peerMss: Int,
        var peerWindow: Int,
        nowNanos: Long,
    ) {
        var state: TcpState = TcpState.SYN_RECEIVED
        var sndUna: Long = serverIsn
        var sndNxt: Long = seqAdd(serverIsn, 1L)
        var rcvNxt: Long = seqAdd(clientIsn, 1L)
        var lastPeerWindow: Int = peerWindow
        var lastAdvertisedRxWindow: Int = processor.availableRxWindow().coerceAtMost(65_535)
        var dupAckCount: Int = 0
        var peerFinReceived: Boolean = false
        var finSent: Boolean = false
        var lastActivityNanos: Long = nowNanos
        var lastZeroWindowProbeNanos: Long = nowNanos
        var timeWaitEnteredNanos: Long = 0L
        val lock = ReentrantLock()
        val unackedSegments = ArrayDeque<SentSegment>()
        val outOfOrder = TreeMap<Long, OutOfOrderSegment>(Comparator { a, b -> seqCompare(a, b) })
        var bufferedOooBytes: Int = 0
    }

    private val sessionTableLock = Any()
    private val sessions = ConcurrentHashMap<TcpFourTuple, TcpSession>()

    private val totalAccepted = AtomicLong()
    private val totalClosedGracefully = AtomicLong()
    private val totalReset = AtomicLong()
    private val sessionsRejectedLimit = AtomicLong()
    private val retransmissions = AtomicLong()
    private val fastRetransmissions = AtomicLong()
    private val zeroWindowEvents = AtomicLong()
    private val duplicateBytesDropped = AtomicLong()
    private val outOfOrderBuffered = AtomicLong()
    private val outOfOrderDropped = AtomicLong()
    private val badChecksumDropped = AtomicLong()
    private val nonTargetPortDropped = AtomicLong()
    private val dnsQueriesProcessed = AtomicLong()

    @Volatile
    private var closed = false

    fun onPacket(packet: ByteArray, length: Int = packet.size): List<ByteArray> {
        if (closed) return emptyList()
        val decoded = when (val res = TunTcpSegmentCodec.decode(packet, length)) {
            is TunTcpSegmentCodec.DecodeResult.Valid -> res.packet
            is TunTcpSegmentCodec.DecodeResult.Invalid -> {
                if (res.reason.contains("checksum") || res.reason.contains("truncated") || res.reason.contains("invalid")) {
                    badChecksumDropped.incrementAndGet()
                }
                return emptyList()
            }
        }

        if (decoded.destinationPort != config.targetPort) {
            nonTargetPortDropped.incrementAndGet()
            return if (!decoded.isRst) listOf(buildStatelessRst(decoded)) else emptyList()
        }

        val key = TcpFourTuple(
            ipv6 = decoded.ipv6,
            clientAddress = decoded.sourceAddress,
            clientPort = decoded.sourcePort,
            serverAddress = decoded.destinationAddress,
            serverPort = decoded.destinationPort,
        )

        val now = clockNanos()
        var session = sessions[key]
        if (session == null) {
            if (decoded.isRst) return emptyList()
            if (!decoded.isSyn || decoded.isAck) {
                return listOf(buildStatelessRst(decoded))
            }
            val created: TcpSession?
            synchronized(sessionTableLock) {
                session = sessions[key]
                if (session == null) {
                    if (closed) return emptyList()
                    if (sessions.size >= config.maxSessions) {
                        sessionsRejectedLimit.incrementAndGet()
                        return listOf(buildStatelessRst(decoded))
                    }
                    val defaultMss = if (decoded.ipv6) config.localMssIpv6 else config.localMssIpv4
                    val appPkg = appIdentityResolver.resolveAppPackage(
                        protocol = 6,
                        sourceAddress = decoded.sourceAddress,
                        sourcePort = decoded.sourcePort,
                        destinationAddress = decoded.destinationAddress,
                        destinationPort = decoded.destinationPort,
                    )
                    val processor = DnsTcpSessionProcessor(
                        evaluateDns = { query, pkg -> engine.evaluateDns(query, pkg) },
                        exchangeUpstream = exchangeUpstream,
                        decoderBufferCapacity = config.decoderBufferBytes,
                        maxFramesPerBatch = config.maxFramesPerBatch,
                        maxPendingOutboundBytes = config.maxPendingOutboundBytes,
                    )
                    val newSession = TcpSession(
                        key = key,
                        processor = processor,
                        appPackage = appPkg,
                        serverIsn = isnProvider() and 0xFFFF_FFFFL,
                        clientIsn = decoded.sequenceNumber,
                        peerMss = (decoded.mss ?: defaultMss).coerceIn(256, defaultMss),
                        peerWindow = decoded.windowSize,
                        nowNanos = now,
                    )
                    sessions[key] = newSession
                    totalAccepted.incrementAndGet()
                    created = newSession
                } else {
                    created = null
                }
            }
            if (created != null) {
                created.lock.withLock {
                    val synAckFlags = TunTcpSegmentCodec.FLAG_SYN or TunTcpSegmentCodec.FLAG_ACK
                    val defaultMss = if (decoded.ipv6) config.localMssIpv6 else config.localMssIpv4
                    val synSeg = SentSegment(
                        seqStart = created.sndUna,
                        seqLen = 1,
                        flags = synAckFlags,
                        payload = ByteArray(0),
                        mssOption = defaultMss,
                        firstSentNanos = now,
                        lastSentNanos = now,
                    )
                    created.unackedSegments.addLast(synSeg)
                    val synAckBytes = encodeSessionSegment(created, synSeg)
                    flowTracker?.recordPacket(
                        key = toFlowKey(key),
                        inBytes = length,
                        outBytes = synAckBytes.size,
                        appPackage = created.appPackage,
                    )
                    return listOf(synAckBytes)
                }
            }
        }

        val active = session ?: return emptyList()
        val outgoing = ArrayList<ByteArray>()
        var removeSession = false

        active.lock.withLock {
            if (active.state == TcpState.CLOSED) return emptyList()
            active.lastActivityNanos = now

            if (decoded.isRst) {
                active.processor.close()
                active.state = TcpState.CLOSED
                active.unackedSegments.clear()
                active.outOfOrder.clear()
                totalReset.incrementAndGet()
                flowTracker?.closeFlow(toFlowKey(key), FlowCloseReason.RST)
                removeSession = true
                return@withLock
            }

            if (active.state == TcpState.TIME_WAIT) {
                if (decoded.isFin) {
                    outgoing += encodeControl(active, TunTcpSegmentCodec.FLAG_ACK, active.sndNxt, active.rcvNxt)
                }
                return@withLock
            }

            // Duplicate SYN while in SYN_RECEIVED: resend SYN+ACK.
            if (active.state == TcpState.SYN_RECEIVED && decoded.isSyn && !decoded.isAck) {
                active.unackedSegments.firstOrNull()?.let { synSeg ->
                    outgoing += encodeSessionSegment(active, synSeg)
                }
                return@withLock
            }

            // ACK processing
            if (decoded.isAck) {
                val ack = decoded.ackNumber
                if (seqGreaterThan(ack, active.sndUna) && seqLessOrEqual(ack, active.sndNxt)) {
                    trimAckedSegments(active, ack)
                    active.sndUna = ack
                    active.dupAckCount = 0
                    active.peerWindow = decoded.windowSize
                    active.lastPeerWindow = decoded.windowSize

                    if (active.state == TcpState.SYN_RECEIVED) {
                        active.state = TcpState.ESTABLISHED
                    } else if (active.state == TcpState.LAST_ACK && active.unackedSegments.isEmpty()) {
                        active.processor.close()
                        totalClosedGracefully.incrementAndGet()
                        flowTracker?.closeFlow(toFlowKey(key), FlowCloseReason.GRACEFUL_FIN)
                        if (config.timeWaitMillis == 0L) {
                            active.state = TcpState.CLOSED
                            removeSession = true
                        } else {
                            active.state = TcpState.TIME_WAIT
                            active.timeWaitEnteredNanos = now
                        }
                        return@withLock
                    }
                } else if (
                    ack == active.sndUna &&
                    decoded.payload.isEmpty() &&
                    !decoded.isFin &&
                    !decoded.isSyn &&
                    active.unackedSegments.isNotEmpty()
                ) {
                    if (decoded.windowSize != active.lastPeerWindow) {
                        active.peerWindow = decoded.windowSize
                        active.lastPeerWindow = decoded.windowSize
                    } else {
                        active.dupAckCount++
                        if (active.dupAckCount == 3) {
                            val head = active.unackedSegments.first()
                            head.retransmitCount++
                            head.lastSentNanos = now
                            retransmissions.incrementAndGet()
                            fastRetransmissions.incrementAndGet()
                            outgoing += encodeSessionSegment(active, head)
                        }
                    }
                } else {
                    active.peerWindow = decoded.windowSize
                    active.lastPeerWindow = decoded.windowSize
                }
            }

            if (active.state == TcpState.SYN_RECEIVED) {
                return@withLock
            }

            var needAck = false

            // Payload handling
            if (decoded.payload.isNotEmpty() && active.state == TcpState.ESTABLISHED) {
                needAck = true
                val segSeq = decoded.sequenceNumber
                val cmp = seqCompare(segSeq, active.rcvNxt)
                when {
                    cmp == 0 -> {
                        val feedResult = feedInOrderPayload(active, decoded.payload)
                        when (feedResult) {
                            FeedOutcome.ACCEPTED -> {
                                drainOutOfOrder(active)
                            }
                            FeedOutcome.BACKPRESSURE -> {
                                zeroWindowEvents.incrementAndGet()
                            }
                            FeedOutcome.TERMINAL_ERROR -> {
                                outgoing += encodeControl(
                                    active,
                                    TunTcpSegmentCodec.FLAG_RST or TunTcpSegmentCodec.FLAG_ACK,
                                    active.sndNxt,
                                    active.rcvNxt,
                                )
                                active.processor.close()
                                active.state = TcpState.CLOSED
                                active.unackedSegments.clear()
                                active.outOfOrder.clear()
                                totalReset.incrementAndGet()
                                removeSession = true
                                return@withLock
                            }
                            FeedOutcome.CLOSED -> {
                                active.processor.close()
                                active.state = TcpState.CLOSED
                                active.unackedSegments.clear()
                                active.outOfOrder.clear()
                                removeSession = true
                                return@withLock
                            }
                        }
                    }
                    cmp < 0 -> {
                        val overlap = seqDiff(active.rcvNxt, segSeq).toInt()
                        if (overlap >= decoded.payload.size) {
                            duplicateBytesDropped.incrementAndGet()
                        } else {
                            duplicateBytesDropped.incrementAndGet()
                            val freshSlice = decoded.payload.copyOfRange(overlap, decoded.payload.size)
                            val feedResult = feedInOrderPayload(active, freshSlice)
                            if (feedResult == FeedOutcome.TERMINAL_ERROR) {
                                outgoing += encodeControl(
                                    active,
                                    TunTcpSegmentCodec.FLAG_RST or TunTcpSegmentCodec.FLAG_ACK,
                                    active.sndNxt,
                                    active.rcvNxt,
                                )
                                active.processor.close()
                                active.state = TcpState.CLOSED
                                active.unackedSegments.clear()
                                active.outOfOrder.clear()
                                totalReset.incrementAndGet()
                                removeSession = true
                                return@withLock
                            } else if (feedResult == FeedOutcome.CLOSED) {
                                active.processor.close()
                                active.state = TcpState.CLOSED
                                active.unackedSegments.clear()
                                active.outOfOrder.clear()
                                removeSession = true
                                return@withLock
                            } else if (feedResult == FeedOutcome.ACCEPTED) {
                                drainOutOfOrder(active)
                            } else {
                                zeroWindowEvents.incrementAndGet()
                            }
                        }
                    }
                    else -> {
                        val gap = seqDiff(segSeq, active.rcvNxt)
                        if (gap <= config.maxBufferedOutOfOrderBytes &&
                            active.bufferedOooBytes + decoded.payload.size <= config.maxBufferedOutOfOrderBytes &&
                            !active.outOfOrder.containsKey(segSeq)
                        ) {
                            active.outOfOrder[segSeq] = OutOfOrderSegment(segSeq, decoded.payload, decoded.isFin)
                            active.bufferedOooBytes += decoded.payload.size
                            outOfOrderBuffered.incrementAndGet()
                        } else {
                            outOfOrderDropped.incrementAndGet()
                        }
                    }
                }
            }

            // FIN handling (only once all prior bytes up to finSeq are received)
            if (decoded.isFin) {
                val finSeq = seqAdd(decoded.sequenceNumber, decoded.payload.size.toLong())
                if (finSeq == active.rcvNxt && !active.peerFinReceived) {
                    active.peerFinReceived = true
                    active.rcvNxt = seqAdd(active.rcvNxt, 1L)
                    if (active.state == TcpState.ESTABLISHED) {
                        active.state = TcpState.CLOSE_WAIT
                    }
                    needAck = true
                } else if (finSeq != active.rcvNxt) {
                    needAck = true
                }
            }

            // Process any deferred frames before emitting responses
            if (active.processor.hasPendingFrames()) {
                val beforeDecoded = active.processor.stats().framesDecoded
                val res = active.processor.processPendingFrames(active.appPackage)
                val afterDecoded = active.processor.stats().framesDecoded
                if (afterDecoded > beforeDecoded) {
                    dnsQueriesProcessed.addAndGet(afterDecoded - beforeDecoded)
                }
                if (res is DnsTcpSessionProcessor.ProcessResult.TerminalError) {
                    outgoing += encodeControl(
                        active,
                        TunTcpSegmentCodec.FLAG_RST or TunTcpSegmentCodec.FLAG_ACK,
                        active.sndNxt,
                        active.rcvNxt,
                    )
                    active.processor.close()
                    active.state = TcpState.CLOSED
                    active.unackedSegments.clear()
                    active.outOfOrder.clear()
                    totalReset.incrementAndGet()
                    flowTracker?.closeFlow(toFlowKey(key), FlowCloseReason.RST)
                    removeSession = true
                    return@withLock
                } else if (res is DnsTcpSessionProcessor.ProcessResult.Closed) {
                    active.processor.close()
                    active.state = TcpState.CLOSED
                    active.unackedSegments.clear()
                    active.outOfOrder.clear()
                    flowTracker?.closeFlow(toFlowKey(key), FlowCloseReason.SHUTDOWN)
                    removeSession = true
                    return@withLock
                }
            }

            val sentDataOrFin = emitOutboundResponses(active, now, outgoing)
            if (needAck && !sentDataOrFin) {
                outgoing += encodeControl(active, TunTcpSegmentCodec.FLAG_ACK, active.sndNxt, active.rcvNxt)
            }
            if (!removeSession && active.state != TcpState.TIME_WAIT && active.state != TcpState.CLOSED) {
                flowTracker?.recordPacket(
                    key = toFlowKey(key),
                    inBytes = length,
                    outBytes = outgoing.sumOf { it.size },
                    appPackage = active.appPackage,
                )
            }
        }

        if (removeSession) {
            removeSessionIfClosed(key, active)
        }
        return outgoing
    }

    fun tick(): List<ByteArray> {
        if (closed) return emptyList()
        val now = clockNanos()
        val outgoing = ArrayList<ByteArray>()
        val idleLimitNanos = config.idleTimeoutMillis * 1_000_000L
        val initialRtoNanos = config.initialRtoMillis * 1_000_000L
        val maxRtoNanos = config.maxRtoMillis * 1_000_000L
        val timeWaitNanos = config.timeWaitMillis * 1_000_000L

        for ((key, session) in sessions.entries) {
            var remove = false
            if (!session.lock.tryLock()) continue
            try {
                if (session.state == TcpState.CLOSED) {
                    remove = true
                } else if (session.state == TcpState.TIME_WAIT) {
                    if (now - session.timeWaitEnteredNanos >= timeWaitNanos) {
                        session.state = TcpState.CLOSED
                        remove = true
                    }
                } else if (now - session.lastActivityNanos >= idleLimitNanos) {
                    outgoing += encodeControl(
                        session,
                        TunTcpSegmentCodec.FLAG_RST or TunTcpSegmentCodec.FLAG_ACK,
                        session.sndNxt,
                        session.rcvNxt,
                    )
                    session.processor.close()
                    session.state = TcpState.CLOSED
                    session.unackedSegments.clear()
                    session.outOfOrder.clear()
                    totalReset.incrementAndGet()
                    flowTracker?.closeFlow(toFlowKey(key), FlowCloseReason.IDLE_TIMEOUT)
                    remove = true
                } else {
                    var terminalFailure = false
                    if (session.processor.hasPendingFrames()) {
                        val before = session.processor.stats().framesDecoded
                        val res = session.processor.processPendingFrames(session.appPackage)
                        val after = session.processor.stats().framesDecoded
                        if (after > before) dnsQueriesProcessed.addAndGet(after - before)
                        if (res is DnsTcpSessionProcessor.ProcessResult.TerminalError) {
                            outgoing += encodeControl(
                                session,
                                TunTcpSegmentCodec.FLAG_RST or TunTcpSegmentCodec.FLAG_ACK,
                                session.sndNxt,
                                session.rcvNxt,
                            )
                            session.processor.close()
                            session.state = TcpState.CLOSED
                            session.unackedSegments.clear()
                            session.outOfOrder.clear()
                            totalReset.incrementAndGet()
                            flowTracker?.closeFlow(toFlowKey(key), FlowCloseReason.RST)
                            remove = true
                            terminalFailure = true
                        } else if (res is DnsTcpSessionProcessor.ProcessResult.Closed) {
                            session.processor.close()
                            session.state = TcpState.CLOSED
                            session.unackedSegments.clear()
                            session.outOfOrder.clear()
                            flowTracker?.closeFlow(toFlowKey(key), FlowCloseReason.SHUTDOWN)
                            remove = true
                            terminalFailure = true
                        }
                    }

                    if (!terminalFailure) {
                        val head = session.unackedSegments.firstOrNull()
                        if (head != null) {
                            val rto = (initialRtoNanos shl head.retransmitCount.coerceAtMost(10)).coerceAtMost(maxRtoNanos)
                            if (now - head.lastSentNanos >= rto) {
                                if (head.retransmitCount >= config.maxRetransmissions) {
                                    outgoing += encodeControl(
                                        session,
                                        TunTcpSegmentCodec.FLAG_RST or TunTcpSegmentCodec.FLAG_ACK,
                                        session.sndNxt,
                                        session.rcvNxt,
                                    )
                                    session.processor.close()
                                    session.state = TcpState.CLOSED
                                    session.unackedSegments.clear()
                                    session.outOfOrder.clear()
                                    totalReset.incrementAndGet()
                                    remove = true
                                    terminalFailure = true
                                } else {
                                    head.retransmitCount++
                                    head.lastSentNanos = now
                                    retransmissions.incrementAndGet()
                                    outgoing += encodeSessionSegment(session, head)
                                }
                            }
                        }
                    }

                    if (!terminalFailure) {
                        val sentOutbound = emitOutboundResponses(session, now, outgoing)
                        val currentRxWin = session.processor.availableRxWindow().coerceAtMost(65_535)
                        if (!sentOutbound && session.lastAdvertisedRxWindow == 0 && currentRxWin > 0) {
                            outgoing += encodeControl(session, TunTcpSegmentCodec.FLAG_ACK, session.sndNxt, session.rcvNxt)
                        }
                        if (session.peerWindow == 0 &&
                            session.processor.pendingOutboundBytes() > 0 &&
                            now - session.lastZeroWindowProbeNanos >= initialRtoNanos
                        ) {
                            session.lastZeroWindowProbeNanos = now
                            outgoing += encodeControl(session, TunTcpSegmentCodec.FLAG_ACK, session.sndNxt, session.rcvNxt)
                        }
                    }
                }
            } finally {
                session.lock.unlock()
            }
            if (remove) {
                removeSessionIfClosed(key, session)
            }
        }
        return outgoing
    }

    fun close() {
        closed = true
        val snapshot: List<TcpSession>
        synchronized(sessionTableLock) {
            snapshot = sessions.values.toList()
            sessions.clear()
        }
        // Cancel any in-flight upstream sockets outside session locks first so workers unblock immediately.
        snapshot.forEach { session -> session.processor.cancelActiveExchange() }
        snapshot.forEach { session ->
            session.lock.withLock {
                session.processor.close()
                session.state = TcpState.CLOSED
                session.unackedSegments.clear()
                session.outOfOrder.clear()
            }
        }
    }

    fun metrics(): TcpStackMetrics = TcpStackMetrics(
        activeSessions = sessions.size,
        totalAccepted = totalAccepted.get(),
        totalClosedGracefully = totalClosedGracefully.get(),
        totalReset = totalReset.get(),
        sessionsRejectedLimit = sessionsRejectedLimit.get(),
        retransmissions = retransmissions.get(),
        fastRetransmissions = fastRetransmissions.get(),
        zeroWindowEvents = zeroWindowEvents.get(),
        duplicateBytesDropped = duplicateBytesDropped.get(),
        outOfOrderBuffered = outOfOrderBuffered.get(),
        outOfOrderDropped = outOfOrderDropped.get(),
        badChecksumDropped = badChecksumDropped.get(),
        nonTargetPortDropped = nonTargetPortDropped.get(),
        dnsQueriesProcessed = dnsQueriesProcessed.get(),
    )

    private enum class FeedOutcome {
        ACCEPTED,
        BACKPRESSURE,
        CLOSED,
        TERMINAL_ERROR,
    }

    private fun feedInOrderPayload(session: TcpSession, bytes: ByteArray): FeedOutcome {
        val beforeDecoded = session.processor.stats().framesDecoded
        val result = session.processor.onIncomingBytes(bytes, appPackage = session.appPackage)
        val afterDecoded = session.processor.stats().framesDecoded
        if (afterDecoded > beforeDecoded) {
            dnsQueriesProcessed.addAndGet(afterDecoded - beforeDecoded)
        }
        return when (result) {
            is DnsTcpSessionProcessor.ProcessResult.Processed -> {
                session.rcvNxt = seqAdd(session.rcvNxt, bytes.size.toLong())
                FeedOutcome.ACCEPTED
            }
            DnsTcpSessionProcessor.ProcessResult.Backpressure -> FeedOutcome.BACKPRESSURE
            DnsTcpSessionProcessor.ProcessResult.Closed -> FeedOutcome.CLOSED
            is DnsTcpSessionProcessor.ProcessResult.TerminalError -> FeedOutcome.TERMINAL_ERROR
        }
    }

    private fun drainOutOfOrder(session: TcpSession) {
        while (session.outOfOrder.isNotEmpty()) {
            val next = session.outOfOrder.firstEntry()?.value ?: break
            if (next.seq != session.rcvNxt) break
            if (feedInOrderPayload(session, next.payload) != FeedOutcome.ACCEPTED) break
            session.outOfOrder.remove(next.seq)
            session.bufferedOooBytes -= next.payload.size
            if (next.isFin && !session.peerFinReceived) {
                session.peerFinReceived = true
                session.rcvNxt = seqAdd(session.rcvNxt, 1L)
                if (session.state == TcpState.ESTABLISHED) {
                    session.state = TcpState.CLOSE_WAIT
                }
            }
        }
    }

    private fun emitOutboundResponses(
        session: TcpSession,
        nowNanos: Long,
        outgoing: MutableList<ByteArray>,
    ): Boolean {
        var emitted = false
        while (
            (session.state == TcpState.ESTABLISHED || session.state == TcpState.CLOSE_WAIT) &&
            session.processor.pendingOutboundBytes() > 0 &&
            session.unackedSegments.size < config.maxUnackedSegmentsPerSession
        ) {
            val inFlight = seqDiff(session.sndNxt, session.sndUna)
            val availWindow = (session.peerWindow.toLong() - inFlight).coerceAtLeast(0L)
            if (availWindow == 0L) {
                if (session.peerWindow == 0) zeroWindowEvents.incrementAndGet()
                break
            }
            val chunkSize = minOf(
                availWindow.toInt(),
                session.peerMss,
                session.processor.pendingOutboundBytes(),
            )
            if (chunkSize <= 0) break
            val chunk = session.processor.pollOutbound(chunkSize)
            if (chunk.isEmpty()) break

            val flags = TunTcpSegmentCodec.FLAG_ACK or
                if (session.processor.pendingOutboundBytes() == 0) TunTcpSegmentCodec.FLAG_PSH else 0
            val seg = SentSegment(
                seqStart = session.sndNxt,
                seqLen = chunk.size,
                flags = flags,
                payload = chunk,
                mssOption = null,
                firstSentNanos = nowNanos,
                lastSentNanos = nowNanos,
            )
            session.unackedSegments.addLast(seg)
            session.sndNxt = seqAdd(session.sndNxt, chunk.size.toLong())
            outgoing += encodeSessionSegment(session, seg)
            emitted = true
        }

        if (session.peerFinReceived &&
            session.state == TcpState.CLOSE_WAIT &&
            session.processor.pendingOutboundBytes() == 0 &&
            !session.processor.hasPendingFrames() &&
            !session.finSent &&
            session.unackedSegments.size < config.maxUnackedSegmentsPerSession
        ) {
            val finSeg = SentSegment(
                seqStart = session.sndNxt,
                seqLen = 1,
                flags = TunTcpSegmentCodec.FLAG_FIN or TunTcpSegmentCodec.FLAG_ACK,
                payload = ByteArray(0),
                mssOption = null,
                firstSentNanos = nowNanos,
                lastSentNanos = nowNanos,
            )
            session.unackedSegments.addLast(finSeg)
            session.sndNxt = seqAdd(session.sndNxt, 1L)
            session.finSent = true
            session.state = TcpState.LAST_ACK
            outgoing += encodeSessionSegment(session, finSeg)
            emitted = true
        }
        return emitted
    }

    private fun trimAckedSegments(session: TcpSession, ack: Long) {
        while (session.unackedSegments.isNotEmpty()) {
            val head = session.unackedSegments.first()
            val headEnd = seqAdd(head.seqStart, head.seqLen.toLong())
            if (seqGreaterOrEqual(ack, headEnd)) {
                session.unackedSegments.removeFirst()
            } else if (
                seqGreaterThan(ack, head.seqStart) &&
                head.payload.isNotEmpty() &&
                (head.flags and (TunTcpSegmentCodec.FLAG_SYN or TunTcpSegmentCodec.FLAG_FIN)) == 0
            ) {
                val ackedBytes = seqDiff(ack, head.seqStart).toInt()
                head.payload = head.payload.copyOfRange(ackedBytes, head.payload.size)
                head.seqStart = ack
                head.seqLen = head.payload.size
                break
            } else {
                break
            }
        }
    }

    private fun encodeSessionSegment(session: TcpSession, segment: SentSegment): ByteArray {
        val rxWindow = session.processor.availableRxWindow().coerceAtMost(65_535)
        session.lastAdvertisedRxWindow = rxWindow
        return TunTcpSegmentCodec.encode(
            ipv6 = session.key.ipv6,
            sourceAddress = session.key.serverAddress,
            destinationAddress = session.key.clientAddress,
            sourcePort = session.key.serverPort,
            destinationPort = session.key.clientPort,
            sequenceNumber = segment.seqStart,
            ackNumber = session.rcvNxt,
            flags = segment.flags,
            windowSize = rxWindow,
            mssOption = segment.mssOption,
            payload = segment.payload,
        )
    }

    private fun encodeControl(
        session: TcpSession,
        flags: Int,
        seq: Long,
        ack: Long,
    ): ByteArray {
        val rxWindow = session.processor.availableRxWindow().coerceAtMost(65_535)
        session.lastAdvertisedRxWindow = rxWindow
        return TunTcpSegmentCodec.encode(
            ipv6 = session.key.ipv6,
            sourceAddress = session.key.serverAddress,
            destinationAddress = session.key.clientAddress,
            sourcePort = session.key.serverPort,
            destinationPort = session.key.clientPort,
            sequenceNumber = seq,
            ackNumber = ack,
            flags = flags,
            windowSize = rxWindow,
        )
    }

    private fun buildStatelessRst(incoming: TunTcpSegmentCodec.DecodedTcpPacket): ByteArray {
        val flags = if (incoming.isAck) {
            TunTcpSegmentCodec.FLAG_RST
        } else {
            TunTcpSegmentCodec.FLAG_RST or TunTcpSegmentCodec.FLAG_ACK
        }
        val seq = if (incoming.isAck) incoming.ackNumber else 0L
        val segLen = incoming.payload.size.toLong() +
            (if (incoming.isSyn) 1L else 0L) +
            (if (incoming.isFin) 1L else 0L)
        val ack = if (incoming.isAck) 0L else seqAdd(incoming.sequenceNumber, segLen)
        return TunTcpSegmentCodec.encode(
            ipv6 = incoming.ipv6,
            sourceAddress = incoming.destinationAddress,
            destinationAddress = incoming.sourceAddress,
            sourcePort = incoming.destinationPort,
            destinationPort = incoming.sourcePort,
            sequenceNumber = seq,
            ackNumber = ack,
            flags = flags,
            windowSize = 0,
        )
    }

    private fun toFlowKey(key: TcpFourTuple): TunFlowTracker.FlowKey = TunFlowTracker.FlowKey(
        protocol = 6,
        ipv6 = key.ipv6,
        clientAddress = key.clientAddress,
        clientPort = key.clientPort,
        serverAddress = key.serverAddress,
        serverPort = key.serverPort,
    )

    private fun removeSessionIfClosed(key: TcpFourTuple, session: TcpSession) {
        synchronized(sessionTableLock) {
            if (sessions[key] === session) {
                sessions.remove(key)
            }
        }
    }

    private companion object {
        fun seqAdd(seq: Long, delta: Long): Long = (seq + delta) and 0xFFFF_FFFFL
        fun seqDiff(a: Long, b: Long): Long = (a - b).toInt().toLong()
        fun seqCompare(a: Long, b: Long): Int = (a - b).toInt().compareTo(0)
        fun seqGreaterThan(a: Long, b: Long): Boolean = (a - b).toInt() > 0
        fun seqLessOrEqual(a: Long, b: Long): Boolean = (a - b).toInt() <= 0
        fun seqGreaterOrEqual(a: Long, b: Long): Boolean = (a - b).toInt() >= 0
    }
}
