package com.firewalldns.engine.monitor

import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.PolicyDecision
import com.firewalldns.engine.core.RuleSource
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.LongAdder

enum class EngineEventType { DNS_BLOCKED, DNS_OBSERVED, DNS_ALLOWED, DNS_REJECTED }

data class EngineEvent(
    val sequence: Long,
    val timestampEpochMillis: Long,
    val type: EngineEventType,
    val reason: String,
    val source: RuleSource?,
    val domain: String?,
    val appPackage: String?,
)

data class EngineMetricsSnapshot(
    val decisions: Long,
    val blocked: Long,
    val observed: Long,
    val allowed: Long,
    val rejected: Long,
    val cacheHits: Long,
    val cacheMisses: Long,
    val eventsDropped: Long,
    val queuedEvents: Int,
)

/**
 * Bounded local telemetry. Recording never performs disk/network I/O and never
 * waits for a consumer. Domain/package details are redacted by default.
 */
class EngineMonitor(
    private val queueCapacity: Int = DEFAULT_QUEUE_CAPACITY,
    private val captureDomains: Boolean = false,
    private val captureAppPackages: Boolean = false,
) {
    private val events = ConcurrentLinkedQueue<EngineEvent>()
    private val queuedEvents = AtomicInteger(0)
    private val sequence = AtomicLong(0)

    private val decisions = LongAdder()
    private val blocked = LongAdder()
    private val observed = LongAdder()
    private val allowed = LongAdder()
    private val rejected = LongAdder()
    private val cacheHits = LongAdder()
    private val cacheMisses = LongAdder()
    private val eventsDropped = LongAdder()

    init {
        require(queueCapacity > 0) { "queueCapacity must be positive" }
    }

    fun recordDecision(
        domain: String?,
        appPackage: String?,
        decision: PolicyDecision,
        timestampEpochMillis: Long,
    ) {
        decisions.increment()
        val type = when (decision.action) {
            PolicyAction.BLOCK -> {
                blocked.increment()
                EngineEventType.DNS_BLOCKED
            }
            PolicyAction.OBSERVE -> {
                observed.increment()
                EngineEventType.DNS_OBSERVED
            }
            PolicyAction.ALLOW -> {
                allowed.increment()
                EngineEventType.DNS_ALLOWED
            }
        }
        offer(
            EngineEvent(
                sequence = sequence.incrementAndGet(),
                timestampEpochMillis = timestampEpochMillis,
                type = type,
                reason = decision.reason,
                source = decision.source,
                domain = domain.takeIf { captureDomains },
                appPackage = appPackage.takeIf { captureAppPackages },
            ),
        )
    }

    fun recordRejected(reason: String, timestampEpochMillis: Long) {
        rejected.increment()
        offer(
            EngineEvent(
                sequence = sequence.incrementAndGet(),
                timestampEpochMillis = timestampEpochMillis,
                type = EngineEventType.DNS_REJECTED,
                reason = reason,
                source = null,
                domain = null,
                appPackage = null,
            ),
        )
    }

    fun recordCacheHit() {
        cacheHits.increment()
    }

    fun recordCacheMiss() {
        cacheMisses.increment()
    }

    /** Returns the oldest queued event, or null when the queue is empty. */
    fun pollEvent(): EngineEvent? {
        val event = events.poll() ?: return null
        queuedEvents.decrementAndGet()
        return event
    }

    fun drainEvents(maxCount: Int): List<EngineEvent> {
        require(maxCount >= 0) { "maxCount must not be negative" }
        return buildList {
            repeat(maxCount) {
                val event = pollEvent() ?: return@repeat
                add(event)
            }
        }
    }

    fun clearEvents() {
        while (pollEvent() != null) Unit
    }

    fun snapshot(): EngineMetricsSnapshot = EngineMetricsSnapshot(
        decisions = decisions.sum(),
        blocked = blocked.sum(),
        observed = observed.sum(),
        allowed = allowed.sum(),
        rejected = rejected.sum(),
        cacheHits = cacheHits.sum(),
        cacheMisses = cacheMisses.sum(),
        eventsDropped = eventsDropped.sum(),
        queuedEvents = queuedEvents.get(),
    )

    private fun offer(event: EngineEvent) {
        while (true) {
            val current = queuedEvents.get()
            if (current >= queueCapacity) {
                eventsDropped.increment()
                return
            }
            if (queuedEvents.compareAndSet(current, current + 1)) break
        }
        events.offer(event)
    }

    private companion object {
        const val DEFAULT_QUEUE_CAPACITY = 512
    }
}
