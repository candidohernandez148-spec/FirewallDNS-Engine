package com.firewalldns.engine.dns

import com.firewalldns.engine.core.PolicyDecision
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

data class DnsDecisionCacheKey(
    val domain: String,
    val appPackage: String?,
    val policyRevision: Long,
)

/**
 * Bounded, non-blocking decision cache.
 *
 * Reads and writes use concurrent primitives only: this cache is consulted on
 * the DNS decision path, so it must never wait for a monitor or disk operation.
 * Entries are scoped to a policy snapshot and expire no later than either the
 * cache TTL or the matched rule's expiry. Under contention eviction is
 * best-effort, while the atomic reservation keeps the entry count bounded.
 */
class DnsDecisionCache(
    private val maxEntries: Int = DEFAULT_MAX_ENTRIES,
    private val ttlMillis: Long = DEFAULT_TTL_MILLIS,
) {
    private data class Entry(val decision: PolicyDecision, val expiresAtEpochMillis: Long)

    private val entries = ConcurrentHashMap<DnsDecisionCacheKey, Entry>()
    private val entryCount = AtomicInteger(0)

    init {
        require(maxEntries > 0) { "maxEntries must be positive" }
        require(ttlMillis > 0) { "ttlMillis must be positive" }
    }

    fun get(key: DnsDecisionCacheKey, nowEpochMillis: Long): PolicyDecision? {
        val entry = entries[key] ?: return null
        if (entry.expiresAtEpochMillis <= nowEpochMillis) {
            if (entries.remove(key, entry)) entryCount.decrementAndGet()
            return null
        }
        return entry.decision
    }

    fun put(key: DnsDecisionCacheKey, decision: PolicyDecision, nowEpochMillis: Long) {
        val expiry = minOf(
            safeAdd(nowEpochMillis, ttlMillis),
            decision.expiresAtEpochMillis ?: Long.MAX_VALUE,
        )
        if (expiry <= nowEpochMillis) return
        val replacement = Entry(decision, expiry)

        while (true) {
            val current = entries[key]
            if (current != null) {
                if (entries.replace(key, current, replacement)) return
                continue
            }

            // Opportunistically reclaim expired entries without blocking readers.
            entries.entries.forEach { (entryKey, entry) ->
                if (entry.expiresAtEpochMillis <= nowEpochMillis &&
                    entries.remove(entryKey, entry)
                ) {
                    entryCount.decrementAndGet()
                }
            }

            if (entryCount.get() >= maxEntries) {
                val victim = entries.entries.firstOrNull()
                if (victim == null) return
                if (entries.remove(victim.key, victim.value)) entryCount.decrementAndGet()
                continue
            }

            val reserved = entryCount.get()
            if (reserved >= maxEntries || !entryCount.compareAndSet(reserved, reserved + 1)) continue
            val previous = entries.putIfAbsent(key, replacement)
            if (previous == null) return

            // Another writer inserted the same key after our initial lookup.
            entryCount.decrementAndGet()
            entries.replace(key, previous, replacement)
            return
        }
    }

    fun clear() {
        // Remove conditionally so concurrent puts are not erased from the count.
        entries.entries.forEach { (key, entry) ->
            if (entries.remove(key, entry)) entryCount.decrementAndGet()
        }
    }

    val size: Int
        get() = entryCount.get()

    private fun safeAdd(left: Long, right: Long): Long =
        if (left > Long.MAX_VALUE - right) Long.MAX_VALUE else left + right

    private companion object {
        const val DEFAULT_MAX_ENTRIES = 4_096
        const val DEFAULT_TTL_MILLIS = 30_000L
    }
}
