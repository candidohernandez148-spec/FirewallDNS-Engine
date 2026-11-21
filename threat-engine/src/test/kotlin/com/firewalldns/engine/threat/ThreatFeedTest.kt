package com.firewalldns.engine.threat

import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.RuleSource
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.KeyPairGenerator
import java.security.spec.ECGenParameterSpec

class ThreatFeedTest {

    private fun generateEcKeyPair() = KeyPairGenerator.getInstance("EC").apply {
        initialize(ECGenParameterSpec("secp256r1"))
    }.generateKeyPair()

    @Test
    fun appliesValidSignedFeedAndRejectsTamperedExpiredOrRollbackFeeds() {
        val kp = generateEcKeyPair()
        val now = 1_700_000_000_000L
        val analyzer = ThreatAnalyzer()

        val initial = analyzer.analyze("c2.malware.example")
        assertEquals(PolicyAction.ALLOW, initial.action)
        assertEquals(0L, analyzer.revision)

        val indicatorsV2 = listOf(
            ThreatIndicator(
                id = "mal-c2",
                domain = "malware.example",
                category = ThreatCategory.MALWARE,
                confidence = 99,
                action = PolicyAction.BLOCK,
                source = RuleSource.MANAGED,
                reason = "curated_c2_feed",
            ),
            ThreatIndicator(
                id = "phish-login",
                domain = "phishing-trap.example",
                category = ThreatCategory.PHISHING,
                confidence = 97,
                action = PolicyAction.BLOCK,
                source = RuleSource.MANAGED,
                reason = "curated_phishing_feed",
            ),
        )
        val feedV2 = ThreatFeedVerifier.sign(
            version = 2L,
            publishedAtEpochMillis = now - 1_000L,
            expiresAtEpochMillis = now + 3_600_000L,
            indicators = indicatorsV2,
            safeDomains = listOf("trusted.example"),
            privateKey = kp.private,
        )

        val applied = analyzer.replaceFeed(feedV2, kp.public, now)
        assertTrue(applied is FeedUpdateResult.Applied)
        assertEquals(1L, analyzer.revision)
        assertEquals(2L, analyzer.feedVersion)
        assertFalse(analyzer.isFeedExpired(now))
        assertTrue(analyzer.isFeedExpired(now + 3_600_001L))

        val malwareHit = analyzer.analyze("c2.malware.example")
        assertEquals(PolicyAction.BLOCK, malwareHit.action)
        assertEquals("curated_c2_feed", malwareHit.reason)

        // Tampered payload rejected without touching active feed
        val tampered = feedV2.copy(
            version = 3L,
            indicators = indicatorsV2 + ThreatIndicator(
                id = "extra",
                domain = "evil.example",
                category = ThreatCategory.MALWARE,
                confidence = 99,
                action = PolicyAction.BLOCK,
                source = RuleSource.MANAGED,
                reason = "tampered",
            ),
        )
        val tamperedResult = analyzer.replaceFeed(tampered, kp.public, now)
        assertEquals(FeedUpdateResult.Rejected("threat_feed_signature_invalid"), tamperedResult)
        assertEquals(PolicyAction.ALLOW, analyzer.analyze("evil.example").action)

        // Version rollback rejected
        val rollback = ThreatFeedVerifier.sign(
            version = 2L,
            publishedAtEpochMillis = now,
            expiresAtEpochMillis = now + 7_200_000L,
            indicators = emptyList(),
            safeDomains = emptyList(),
            privateKey = kp.private,
        )
        assertEquals(FeedUpdateResult.Rejected("threat_feed_version_not_newer"), analyzer.replaceFeed(rollback, kp.public, now))

        // Expired feed rejected
        val expired = ThreatFeedVerifier.sign(
            version = 3L,
            publishedAtEpochMillis = now - 10_000L,
            expiresAtEpochMillis = now - 1L,
            indicators = emptyList(),
            safeDomains = emptyList(),
            privateKey = kp.private,
        )
        assertEquals(FeedUpdateResult.Rejected("threat_feed_expired"), analyzer.replaceFeed(expired, kp.public, now))
        assertEquals(2L, analyzer.feedVersion)
    }

    @Test
    fun lexicalPhishingAndTrackingHeuristicsOnlyObserveNeverBlock() {
        val analyzer = ThreatAnalyzer()
        val suspicious = analyzer.analyze("verify-account.portal.example")
        assertEquals(PolicyAction.OBSERVE, suspicious.action)
        assertEquals(RuleSource.HEURISTIC, suspicious.source)
    }
}
