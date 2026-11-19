package com.firewalldns.engine.dns

import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.PolicyDecision
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class DnsDecisionCacheTest {
    @Test fun returnsCachedDecisionUntilTtlExpires() {
        val cache = DnsDecisionCache(maxEntries = 4, ttlMillis = 100)
        val key = DnsDecisionCacheKey("ads.example.com", null, 1)
        val decision = PolicyDecision(PolicyAction.BLOCK, "test", policyRevision = 1)
        cache.put(key, decision, 1_000)
        assertEquals(decision, cache.get(key, 1_099))
        assertNull(cache.get(key, 1_100))
    }

    @Test fun ruleExpiryShortensCacheLifetime() {
        val cache = DnsDecisionCache(maxEntries = 4, ttlMillis = 10_000)
        val key = DnsDecisionCacheKey("ads.example.com", null, 1)
        val decision = PolicyDecision(
            PolicyAction.BLOCK,
            "expiring_rule",
            policyRevision = 1,
            expiresAtEpochMillis = 1_050,
        )
        cache.put(key, decision, 1_000)
        assertEquals(decision, cache.get(key, 1_049))
        assertNull(cache.get(key, 1_050))
    }

    @Test fun enforcesMaximumEntryCount() {
        val cache = DnsDecisionCache(maxEntries = 2, ttlMillis = 1_000)
        repeat(3) { index ->
            val key = DnsDecisionCacheKey("d$index.example", null, 1)
            cache.put(key, PolicyDecision(PolicyAction.ALLOW, "test", policyRevision = 1), 1)
        }
        assertEquals(2, cache.size)
    }

    @Test fun clearRemovesAllEntries() {
        val cache = DnsDecisionCache()
        cache.put(
            DnsDecisionCacheKey("example.com", null, 1),
            PolicyDecision(PolicyAction.ALLOW, "test", policyRevision = 1),
            1,
        )
        cache.clear()
        assertEquals(0, cache.size)
    }

    @Test fun policyRevisionIsPartOfTheCacheKey() {
        val cache = DnsDecisionCache()
        val oldKey = DnsDecisionCacheKey("example.com", null, 1)
        val newKey = DnsDecisionCacheKey("example.com", null, 2)
        cache.put(oldKey, PolicyDecision(PolicyAction.BLOCK, "old", policyRevision = 1), 1)
        assertNull(cache.get(newKey, 2))
    }
}
