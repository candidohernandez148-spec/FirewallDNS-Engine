package com.firewalldns.engine.android

import com.firewalldns.engine.dns.DnsExchangeCancellation
import com.firewalldns.engine.dns.DnsResponseCache
import com.firewalldns.engine.dns.DnsSocketProtector
import com.firewalldns.engine.dns.DnsUpstreamClient
import com.firewalldns.engine.dns.DnsUpstreamFailoverClient
import com.firewalldns.engine.dns.DnsUpstreamResult
import com.firewalldns.engine.runtime.EngineRuntime
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicLong

data class TunDataPlaneMetrics(
    val validation: TunDataPlaneValidationResult,
    val packetsEntered: Long,
    val udpResponsesOut: Long,
    val tcpSegmentsOut: Long,
    val tcpSegmentsConsumed: Long,
    val fragmentsPendingDropped: Long,
    val loopsBlocked: Long,
    val dnsLeaksBlocked: Long,
    val runtimeProtectFailClosedBlocked: Long,
    val noResponseCount: Long,
    val socketProtection: SocketProtectionAuditSnapshot,
    val fragmentReassembly: FragmentReassemblerMetrics,
    val tcpStack: TcpStackMetrics,
    val flows: TunFlowTrackerSnapshot,
    val appIdentity: AppIdentityMetricsSnapshot,
)

/**
 * Validated production TUN data-plane coordinator unifying:
 * - Preflight validation of VpnService.protect(), loop-freedom, and zero-DNS-leak invariants
 * - Bounded IPv4/IPv6 fragment reassembly
 * - Runtime loop and DoT/bypass leak guards with fail-closed socket protection monitoring
 * - Per-flow Android UID/package attribution with explicit degradation
 * - Bounded flow tracking with TTL eviction and close reasons
 * - IPv4/IPv6 UDP/53 (with IPv6 extension headers) and per-session TCP/53 processing
 */
class TunDataPlaneCoordinator private constructor(
    val validation: TunDataPlaneValidationResult,
    private val engine: EngineRuntime,
    private val auditedProtector: AuditedDnsSocketProtector,
    private val failoverClient: DnsUpstreamFailoverClient,
    securityConfig: TunDataPlaneSecurityConfig,
    tcpStackConfig: TunTcpStackConfig,
    fragmentConfig: FragmentReassemblerConfig,
    flowTrackerConfig: TunFlowTrackerConfig,
    private val appIdentityResolver: AppIdentityResolver,
    private val clockNanos: () -> Long,
) {
    sealed interface ActivationResult {
        data class Activated(val coordinator: TunDataPlaneCoordinator) : ActivationResult
        data class Rejected(val validation: TunDataPlaneValidationResult) : ActivationResult
    }

    sealed interface PacketHandlingResult {
        data class Responses(val packets: List<ByteArray>, val outcome: String) : PacketHandlingResult
        data class Consumed(val outcome: String) : PacketHandlingResult
        data class BlockedOrDropped(val outcome: String, val responsePackets: List<ByteArray> = emptyList()) : PacketHandlingResult
    }

    private val inFlightCancellations = ConcurrentHashMap.newKeySet<DnsExchangeCancellation>()
    private val fragmentReassembler = IpFragmentReassembler(fragmentConfig, clockNanos)
    private val loopAndLeakGuard = LoopAndLeakGuard(securityConfig)
    private val flowTracker = TunFlowTracker(flowTrackerConfig, clockNanos)
    private val udpProcessor = TunDnsPacketProcessor.withCancellation(
        engine = engine,
        appIdentityResolver = appIdentityResolver,
        flowTracker = flowTracker,
    ) { query, cancellation ->
        guardedUpstreamExchange(query, cancellation)
    }
    private val tcpStack = TunTcpStack(
        engine = engine,
        exchangeUpstream = { query, cancellation -> guardedUpstreamExchange(query, cancellation) },
        config = tcpStackConfig,
        clockNanos = clockNanos,
        appIdentityResolver = appIdentityResolver,
        flowTracker = flowTracker,
    )

    private val packetsEntered = AtomicLong()
    private val udpResponsesOut = AtomicLong()
    private val tcpSegmentsOut = AtomicLong()
    private val tcpSegmentsConsumed = AtomicLong()
    private val fragmentsPendingOrDropped = AtomicLong()
    private val loopsBlocked = AtomicLong()
    private val dnsLeaksBlocked = AtomicLong()
    private val runtimeProtectFailClosedBlocked = AtomicLong()
    private val noResponseCount = AtomicLong()

    @Volatile
    private var closed = false

    fun onPacket(
        packet: ByteArray,
        length: Int = packet.size,
        processTcp: Boolean = true,
    ): PacketHandlingResult {
        if (closed) return PacketHandlingResult.BlockedOrDropped("data_plane_closed")
        packetsEntered.incrementAndGet()

        val readyPacket: ByteArray
        val readyLength: Int
        when (val reassembly = fragmentReassembler.process(packet, length)) {
            is IpFragmentReassembler.Result.Pending -> {
                fragmentsPendingOrDropped.incrementAndGet()
                return PacketHandlingResult.Consumed("ip_fragment_buffered_pending")
            }
            is IpFragmentReassembler.Result.Dropped -> {
                fragmentsPendingOrDropped.incrementAndGet()
                return PacketHandlingResult.BlockedOrDropped(reassembly.reason)
            }
            is IpFragmentReassembler.Result.Ready -> {
                readyPacket = reassembly.packet
                readyLength = reassembly.length
            }
        }

        when (val guard = loopAndLeakGuard.inspect(readyPacket, readyLength)) {
            is LoopAndLeakGuard.Decision.LoopBlocked -> {
                loopsBlocked.incrementAndGet()
                return PacketHandlingResult.BlockedOrDropped(guard.reason)
            }
            is LoopAndLeakGuard.Decision.LeakBlocked -> {
                dnsLeaksBlocked.incrementAndGet()
                val responses = guard.responsePacket?.let { listOf(it) } ?: emptyList()
                return PacketHandlingResult.BlockedOrDropped(guard.reason, responses)
            }
            LoopAndLeakGuard.Decision.Allow -> Unit
        }

        return if (isTcpPacket(readyPacket, readyLength)) {
            if (!processTcp) {
                return PacketHandlingResult.Consumed("dns_tcp_delegated_to_smoltcp")
            }
            val out = tcpStack.onPacket(readyPacket, readyLength)
            if (out.isEmpty()) {
                tcpSegmentsConsumed.incrementAndGet()
                PacketHandlingResult.Consumed("dns_tcp_segment_consumed")
            } else {
                tcpSegmentsOut.addAndGet(out.size.toLong())
                PacketHandlingResult.Responses(out, "dns_tcp_segment_out")
            }
        } else {
            val udpCancellation = DnsExchangeCancellation()
            when (val res = udpProcessor.processDetailed(readyPacket, readyLength, udpCancellation)) {
                is TunDnsPacketProcessor.PacketResult.Response -> {
                    udpResponsesOut.incrementAndGet()
                    PacketHandlingResult.Responses(listOf(res.packet), res.outcome)
                }
                is TunDnsPacketProcessor.PacketResult.NoResponse -> {
                    noResponseCount.incrementAndGet()
                    PacketHandlingResult.BlockedOrDropped(res.reason)
                }
            }
        }
    }

    fun tick(): List<ByteArray> {
        if (closed) return emptyList()
        fragmentReassembler.evictExpired()
        flowTracker.evictExpired()
        val out = tcpStack.tick()
        if (out.isNotEmpty()) {
            tcpSegmentsOut.addAndGet(out.size.toLong())
        }
        return out
    }

    fun close() {
        closed = true
        inFlightCancellations.forEach { it.cancel() }
        inFlightCancellations.clear()
        tcpStack.close()
        fragmentReassembler.clear()
        flowTracker.closeAll(FlowCloseReason.SHUTDOWN)
    }

    fun metrics(): TunDataPlaneMetrics = TunDataPlaneMetrics(
        validation = validation,
        packetsEntered = packetsEntered.get(),
        udpResponsesOut = udpResponsesOut.get(),
        tcpSegmentsOut = tcpSegmentsOut.get(),
        tcpSegmentsConsumed = tcpSegmentsConsumed.get(),
        fragmentsPendingDropped = fragmentsPendingOrDropped.get(),
        loopsBlocked = loopsBlocked.get(),
        dnsLeaksBlocked = dnsLeaksBlocked.get(),
        runtimeProtectFailClosedBlocked = runtimeProtectFailClosedBlocked.get(),
        noResponseCount = noResponseCount.get(),
        socketProtection = auditedProtector.snapshot(),
        fragmentReassembly = fragmentReassembler.metrics(),
        tcpStack = tcpStack.metrics(),
        flows = flowTracker.snapshot(),
        appIdentity = appIdentityResolver.metrics(),
    )

    /** Reuses the audited VpnService.protect() path for native TCP DNS sessions. */
    fun exchangeProtectedUpstream(
        query: ByteArray,
        cancellation: DnsExchangeCancellation,
    ): DnsUpstreamResult = guardedUpstreamExchange(query, cancellation)

    private fun guardedUpstreamExchange(
        query: ByteArray,
        cancellation: DnsExchangeCancellation,
    ): DnsUpstreamResult {
        if (closed || cancellation.isCancelled) return DnsUpstreamResult.Cancelled
        if (auditedProtector.hasFailures()) {
            runtimeProtectFailClosedBlocked.incrementAndGet()
            return DnsUpstreamResult.Failure("runtime_socket_protect_fail_closed")
        }
        inFlightCancellations.add(cancellation)
        if (closed) {
            inFlightCancellations.remove(cancellation)
            cancellation.cancel()
            return DnsUpstreamResult.Cancelled
        }
        return try {
            val failuresBefore = auditedProtector.snapshot().totalFailures
            val result = failoverClient.exchange(query, cancellation)
            if (auditedProtector.hasFailures() &&
                (result is DnsUpstreamResult.Success || auditedProtector.snapshot().totalFailures > failuresBefore)
            ) {
                runtimeProtectFailClosedBlocked.incrementAndGet()
                DnsUpstreamResult.Failure("runtime_socket_protect_fail_closed")
            } else {
                result
            }
        } finally {
            inFlightCancellations.remove(cancellation)
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
                while (next in IPV6_EXTENSION_HEADERS) {
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

    companion object {
        private val IPV6_EXTENSION_HEADERS = setOf(0, 43, 44, 51, 60)

        fun createValidated(
            engine: EngineRuntime,
            rawProtector: DnsSocketProtector,
            securityConfig: TunDataPlaneSecurityConfig,
            responseCache: DnsResponseCache = DnsResponseCache(),
            tcpStackConfig: TunTcpStackConfig = TunTcpStackConfig(),
            fragmentConfig: FragmentReassemblerConfig = FragmentReassemblerConfig(),
            flowTrackerConfig: TunFlowTrackerConfig = TunFlowTrackerConfig(),
            appIdentityResolver: AppIdentityResolver = NoopAppIdentityResolver,
            clockNanos: () -> Long = System::nanoTime,
        ): ActivationResult {
            val validation = TunDataPlaneSecurityValidator.validatePreflight(securityConfig, rawProtector)
            if (!validation.passed) {
                return ActivationResult.Rejected(validation)
            }
            val audited = AuditedDnsSocketProtector(rawProtector)
            val clients = securityConfig.upstreamConfigs.map { cfg ->
                DnsUpstreamClient(cfg, audited, responseCache, clockNanos)
            }
            val failover = DnsUpstreamFailoverClient(clients, clients.size)
            return ActivationResult.Activated(
                TunDataPlaneCoordinator(
                    validation = validation,
                    engine = engine,
                    auditedProtector = audited,
                    failoverClient = failover,
                    securityConfig = securityConfig,
                    tcpStackConfig = tcpStackConfig,
                    fragmentConfig = fragmentConfig,
                    flowTrackerConfig = flowTrackerConfig,
                    appIdentityResolver = appIdentityResolver,
                    clockNanos = clockNanos,
                ),
            )
        }
    }
}
