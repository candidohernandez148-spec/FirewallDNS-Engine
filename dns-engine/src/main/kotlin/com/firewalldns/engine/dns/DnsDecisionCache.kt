package com.firewalldns.engine.dns

import com.firewalldns.engine.core.PolicyDecision
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.withLock

data class DnsDecisionCacheKey(
    val domain: String,
    val appPackage: String?,
    val policyRevision: Long,
)

/**
 * Bounded, thread-safe decision cache.
 *
 * Reads are lock-free. Writes use a short lock to enforce the configured hard
 * entry limit. Entries are scoped to a policy snapshot and expire no later than
 * either the cache TTL or the matched rule's expiry.
 */
class DnsDecisionCache(
    private val maxEntries: Int = DEFAULT_MAX_ENTRIES,
    private val ttlMillis: Long = DEFAULT_TTL_MILLIS,
) {
    private data class Entry(val decision: PolicyDecision, val expiresAtEpochMillis: Long)

    private val entries = ConcurrentHashMap<DnsDecisionCacheKey, Entry>()
    private val writeLock = ReentrantLock()

    init {
        require(maxEntries > 0) { "maxEntries must be positive" }
        require(ttlMillis > 0) { "ttlMillis must be positive" }
    }

    fun get(key: DnsDecisionCacheKey, nowEpochMillis: Long): PolicyDecision? {
        val entry = entries[key] ?: return null
        if (entry.expiresAtEpochMillis <= nowEpochMillis) {
            entries.remove(key, entry)
            return null
        }
        return entry.decision
    }

    fun put(key: DnsDecisionCacheKey, decision: PolicyDecision, nowEpochMillis: Long) {
        val ttlExpiry = safeAdd(nowEpochMillis, ttlMillis)
        val expiry = minOf(ttlExpiry, decision.expiresAtEpochMillis ?: Long.MAX_VALUE)
        if (expiry <= nowEpochMillis) return

        writeLock.withLock {
            // Remove expired entries first so they do not evict live decisions.
            entries.entries.removeIf { it.value.expiresAtEpochMillis <= nowEpochMillis }
            if (!entries.containsKey(key) && entries.size >= maxEntries) {
                val victim = entries.keys.firstOrNull()
                if (victim != null) entries.remove(victim)
            }
            entries[key] = Entry(decision, expiry)
        }
    }

    fun clear() {
        writeLock.withLock { entries.clear() }
    }

    val size: Int
        get() = entries.size

    private fun safeAdd(left: Long, right: Long): Long =
        if (left > Long.MAX_VALUE - right) Long.MAX_VALUE else left + right

    private companion object {
        const val DEFAULT_MAX_ENTRIES = 4_096
        const val DEFAULT_TTL_MILLIS = 30_000L
    }
}
