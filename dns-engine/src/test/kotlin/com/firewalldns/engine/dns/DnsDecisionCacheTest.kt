package com.firewalldns.engine.dns

import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.PolicyDecision
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

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

    @Test fun concurrentWritersNeverExceedConfiguredBound() {\n        val cache = DnsDecisionCache(maxEntries = 32, ttlMillis = 10_000)\n        val workers = 8\n        val iterations = 1_000\n        val ready = CountDownLatch(workers)\n        val start = CountDownLatch(1)\n        val executor = Executors.newFixedThreadPool(workers)\n        try {\n            repeat(workers) { worker ->\n                executor.execute {\n                    ready.countDown()\n                    start.await()\n                    repeat(iterations) { index ->\n                        val key = DnsDecisionCacheKey("d${worker}_$index.example", null, 1)\n                        cache.put(key, PolicyDecision(PolicyAction.ALLOW, "stress", policyRevision = 1), 1)\n                    }\n                }\n            }\n            ready.await(5, TimeUnit.SECONDS)\n            start.countDown()\n            executor.shutdown()\n            check(executor.awaitTermination(10, TimeUnit.SECONDS))\n            assertEquals(32, cache.size)\n        } finally {\n            executor.shutdownNow()\n        }\n    }\n\n    @Test fun clearRemovesAllEntries() {
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
