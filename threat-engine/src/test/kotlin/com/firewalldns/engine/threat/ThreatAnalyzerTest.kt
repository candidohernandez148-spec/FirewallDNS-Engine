package com.firewalldns.engine.threat

import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.RuleSource
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class ThreatAnalyzerTest {
    private val analyzer = ThreatAnalyzer()

    @Test fun knownAdDeliveryDomainIsBlocked() {
        val result = analyzer.analyze("img.doubleclick.net")
        assertEquals(PolicyAction.BLOCK, result.action)
        assertEquals("ads-doubleclick", result.indicatorId)
        assertEquals(ThreatCategory.ADVERTISING, result.signals.single().category)
    }

    @Test fun knownTrackerIsObservedRatherThanBlocked() {
        val result = analyzer.analyze("pixel.facebook.com")
        assertEquals(PolicyAction.OBSERVE, result.action)
        assertEquals(ThreatCategory.TRACKING, result.signals.single().category)
    }

    @Test fun heuristicAdAndTrackingLabelsOnlyProduceObserve() {
        val result = analyzer.analyze("ads-tracker.example.com")
        assertEquals(PolicyAction.OBSERVE, result.action)
        assertEquals(2, result.signals.size)
        assertTrue(result.riskScore in 1..100)
    }

    @Test fun essentialServiceDomainsAvoidLexicalHeuristics() {
        val result = analyzer.analyze("metrics.youtube.com")
        assertEquals(PolicyAction.ALLOW, result.action)
        assertEquals("trusted_domain_allowlist", result.reason)
    }

    @Test fun domainBoundaryPreventsLookalikeSuffixMatches() {
        val result = analyzer.analyze("notdoubleclick.net")
        assertEquals(PolicyAction.ALLOW, result.action)
    }

    @Test fun invalidDomainIsNotBlocked() {
        val result = analyzer.analyze("bad domain")
        assertEquals(PolicyAction.ALLOW, result.action)
        assertEquals("invalid_domain_input", result.reason)
    }

    @Test fun blockingIndicatorRequiresHighConfidence() {
        assertFailsWith<IllegalArgumentException> {
            ThreatAnalyzer(
                indicators = listOf(
                    ThreatIndicator(
                        id = "weak",
                        domain = "weak.example",
                        category = ThreatCategory.MALWARE,
                        confidence = 50,
                        action = PolicyAction.BLOCK,
                        reason = "weak_signal",
                    ),
                ),
                safeDomains = emptyList(),
            )
        }
    }

    @Test fun indicatorCanBeScopedToExactDomain() {
        val custom = ThreatAnalyzer(
            indicators = listOf(
                ThreatIndicator(
                    id = "exact",
                    domain = "bad.example",
                    includeSubdomains = false,
                    category = ThreatCategory.MALWARE,
                    confidence = 99,
                    action = PolicyAction.BLOCK,
                    source = RuleSource.MANAGED,
                    reason = "verified_test_indicator",
                ),
            ),
            safeDomains = emptyList(),
        )
        assertEquals(PolicyAction.BLOCK, custom.analyze("bad.example").action)
        assertEquals(PolicyAction.ALLOW, custom.analyze("sub.bad.example").action)
    }
}
