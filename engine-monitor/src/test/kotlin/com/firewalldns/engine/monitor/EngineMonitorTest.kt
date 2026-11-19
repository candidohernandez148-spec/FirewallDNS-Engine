package com.firewalldns.engine.monitor

import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.PolicyDecision
import com.firewalldns.engine.core.RuleSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class EngineMonitorTest {
    @Test fun countsDecisionsCacheResultsAndRejectedMessages() {
        val monitor = EngineMonitor(queueCapacity = 8)
        monitor.recordDecision(null, null, PolicyDecision(PolicyAction.BLOCK, "known_ad", source = RuleSource.BUILTIN), 1)
        monitor.recordDecision(null, null, PolicyDecision(PolicyAction.OBSERVE, "heuristic"), 2)
        monitor.recordDecision(null, null, PolicyDecision(PolicyAction.ALLOW, "safe"), 3)
        monitor.recordRejected("malformed_dns", 4)
        monitor.recordCacheHit()
        monitor.recordCacheMiss()

        val metrics = monitor.snapshot()
        assertEquals(3, metrics.decisions)
        assertEquals(1, metrics.blocked)
        assertEquals(1, metrics.observed)
        assertEquals(1, metrics.allowed)
        assertEquals(1, metrics.rejected)
        assertEquals(1, metrics.cacheHits)
        assertEquals(1, metrics.cacheMisses)
        assertEquals(4, metrics.queuedEvents)
    }

    @Test fun eventQueueIsBoundedAndDropsAreCounted() {
        val monitor = EngineMonitor(queueCapacity = 1, captureDomains = true)
        monitor.recordDecision("ads.example.com", null, PolicyDecision(PolicyAction.BLOCK, "blocked"), 1)
        monitor.recordDecision("safe.example.com", null, PolicyDecision(PolicyAction.ALLOW, "allowed"), 2)

        assertEquals(1, monitor.snapshot().queuedEvents)
        assertEquals(1, monitor.snapshot().eventsDropped)
        assertEquals("ads.example.com", monitor.pollEvent()?.domain)
        assertNull(monitor.pollEvent())
    }

    @Test fun sensitiveFieldsAreRedactedByDefault() {
        val monitor = EngineMonitor()
        monitor.recordDecision(
            "private.example.com",
            "com.example.private",
            PolicyDecision(PolicyAction.BLOCK, "test"),
            10,
        )
        val event = monitor.pollEvent()!!
        assertNull(event.domain)
        assertNull(event.appPackage)
    }

    @Test fun canOptInToLocalDomainAndPackageDetails() {
        val monitor = EngineMonitor(captureDomains = true, captureAppPackages = true)
        monitor.recordDecision(
            "ads.example.com",
            "com.example.browser",
            PolicyDecision(PolicyAction.OBSERVE, "test"),
            10,
        )
        val event = monitor.pollEvent()!!
        assertEquals("ads.example.com", event.domain)
        assertEquals("com.example.browser", event.appPackage)
    }

    @Test fun drainAndClearRespectQueueState() {
        val monitor = EngineMonitor(queueCapacity = 4)
        repeat(3) { monitor.recordRejected("bad", it.toLong()) }
        assertEquals(2, monitor.drainEvents(2).size)
        assertEquals(1, monitor.snapshot().queuedEvents)
        monitor.clearEvents()
        assertEquals(0, monitor.snapshot().queuedEvents)
    }
}
