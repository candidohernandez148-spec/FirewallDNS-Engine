package com.firewalldns.engine.android

import java.util.LinkedHashMap

enum class FlowCloseReason {
    IDLE_TIMEOUT,
    GRACEFUL_FIN,
    RST,
    POLICY_BLOCKED,
    EVICTED_CAPACITY,
    SHUTDOWN,
}

data class TunFlowTrackerConfig(
    val maxActiveFlows: Int = 1_024,
    val idleTimeoutMillis: Long = 30_000L,
    val captureAppPackages: Boolean = false,
) {
    init {
        require(maxActiveFlows in 8..16_384)
        require(idleTimeoutMillis > 0L)
    }
}

data class TunFlowTrackerSnapshot(
    val activeFlows: Int,
    val totalOpened: Long,
    val closedGracefulFin: Long,
    val closedRst: Long,
    val closedPolicyBlocked: Long,
    val closedIdleTimeout: Long,
    val closedEvictedCapacity: Long,
    val closedShutdown: Long,
    val bytesIn: Long,
    val bytesOut: Long,
)

/**
 * Bounded, privacy-preserving DNS flow tracker with strict memory caps,
 * monotonic idle TTL eviction, and explicit close causes (no payload retained).
 */
class TunFlowTracker(
    private val config: TunFlowTrackerConfig = TunFlowTrackerConfig(),
    private val clockNanos: () -> Long = System::nanoTime,
) {
    data class FlowKey(
        val protocol: Int,
        val ipv6: Boolean,
        val clientAddress: ByteArray,
        val clientPort: Int,
        val serverAddress: ByteArray,
        val serverPort: Int,
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is FlowKey) return false
            return protocol == other.protocol &&
                ipv6 == other.ipv6 &&
                clientPort == other.clientPort &&
                serverPort == other.serverPort &&
                clientAddress.contentEquals(other.clientAddress) &&
                serverAddress.contentEquals(other.serverAddress)
        }

        override fun hashCode(): Int {
            var h = protocol
            h = 31 * h + ipv6.hashCode()
            h = 31 * h + clientAddress.contentHashCode()
            h = 31 * h + clientPort
            h = 31 * h + serverAddress.contentHashCode()
            h = 31 * h + serverPort
            return h
        }
    }

    private class FlowState(
        var lastSeenNanos: Long,
        var packetsIn: Long = 0L,
        var packetsOut: Long = 0L,
        var bytesIn: Long = 0L,
        var bytesOut: Long = 0L,
        var appPackage: String? = null,
    )

    private val lock = Any()
    private val activeFlows = LinkedHashMap<FlowKey, FlowState>(64, 0.75f, true)
    private val idleTimeoutNanos = config.idleTimeoutMillis * 1_000_000L

    private var totalOpened = 0L
    private var closedGracefulFin = 0L
    private var closedRst = 0L
    private var closedPolicyBlocked = 0L
    private var closedIdleTimeout = 0L
    private var closedEvictedCapacity = 0L
    private var closedShutdown = 0L
    private var totalBytesIn = 0L
    private var totalBytesOut = 0L

    fun recordPacket(
        key: FlowKey,
        inBytes: Int,
        outBytes: Int = 0,
        appPackage: String? = null,
    ) {
        val now = clockNanos()
        synchronized(lock) {
            evictExpiredLocked(now)
            var state = activeFlows[key]
            if (state == null) {
                if (activeFlows.size >= config.maxActiveFlows) {
                    val eldestKey = activeFlows.keys.firstOrNull()
                    if (eldestKey != null && activeFlows.remove(eldestKey) != null) {
                        closedEvictedCapacity++
                    }
                }
                state = FlowState(
                    lastSeenNanos = now,
                    appPackage = appPackage.takeIf { config.captureAppPackages },
                )
                activeFlows[key] = state
                totalOpened++
            } else {
                state.lastSeenNanos = now
                if (config.captureAppPackages && state.appPackage == null && appPackage != null) {
                    state.appPackage = appPackage
                }
            }
            if (inBytes > 0) {
                state.packetsIn++
                state.bytesIn += inBytes.toLong()
                totalBytesIn += inBytes.toLong()
            }
            if (outBytes > 0) {
                state.packetsOut++
                state.bytesOut += outBytes.toLong()
                totalBytesOut += outBytes.toLong()
            }
        }
    }

    fun closeFlow(key: FlowKey, reason: FlowCloseReason) {
        synchronized(lock) {
            if (activeFlows.remove(key) != null) {
                incrementCloseCounterLocked(reason)
            }
        }
    }

    fun evictExpired(): Int {
        synchronized(lock) {
            return evictExpiredLocked(clockNanos())
        }
    }

    fun closeAll(reason: FlowCloseReason = FlowCloseReason.SHUTDOWN) {
        synchronized(lock) {
            val count = activeFlows.size.toLong()
            if (count > 0L) {
                activeFlows.clear()
                when (reason) {
                    FlowCloseReason.IDLE_TIMEOUT -> closedIdleTimeout += count
                    FlowCloseReason.GRACEFUL_FIN -> closedGracefulFin += count
                    FlowCloseReason.RST -> closedRst += count
                    FlowCloseReason.POLICY_BLOCKED -> closedPolicyBlocked += count
                    FlowCloseReason.EVICTED_CAPACITY -> closedEvictedCapacity += count
                    FlowCloseReason.SHUTDOWN -> closedShutdown += count
                }
            }
        }
    }

    fun snapshot(): TunFlowTrackerSnapshot = synchronized(lock) {
        TunFlowTrackerSnapshot(
            activeFlows = activeFlows.size,
            totalOpened = totalOpened,
            closedGracefulFin = closedGracefulFin,
            closedRst = closedRst,
            closedPolicyBlocked = closedPolicyBlocked,
            closedIdleTimeout = closedIdleTimeout,
            closedEvictedCapacity = closedEvictedCapacity,
            closedShutdown = closedShutdown,
            bytesIn = totalBytesIn,
            bytesOut = totalBytesOut,
        )
    }

    private fun evictExpiredLocked(nowNanos: Long): Int {
        var evicted = 0
        val iter = activeFlows.entries.iterator()
        while (iter.hasNext()) {
            val entry = iter.next()
            if (nowNanos - entry.value.lastSeenNanos >= idleTimeoutNanos) {
                iter.remove()
                closedIdleTimeout++
                evicted++
            }
        }
        return evicted
    }

    private fun incrementCloseCounterLocked(reason: FlowCloseReason) {
        when (reason) {
            FlowCloseReason.IDLE_TIMEOUT -> closedIdleTimeout++
            FlowCloseReason.GRACEFUL_FIN -> closedGracefulFin++
            FlowCloseReason.RST -> closedRst++
            FlowCloseReason.POLICY_BLOCKED -> closedPolicyBlocked++
            FlowCloseReason.EVICTED_CAPACITY -> closedEvictedCapacity++
            FlowCloseReason.SHUTDOWN -> closedShutdown++
        }
    }
}
