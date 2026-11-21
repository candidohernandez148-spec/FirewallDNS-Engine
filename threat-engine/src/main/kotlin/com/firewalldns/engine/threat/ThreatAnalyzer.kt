package com.firewalldns.engine.threat

import com.firewalldns.engine.core.DomainNormalizer
import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.RuleSource
import java.security.PublicKey
import java.util.concurrent.atomic.AtomicReference

/**
 * Local, explainable domain reputation. Trusted curated indicators (and verified
 * signed feeds) may block; lexical heuristics only OBSERVE and therefore never
 * block on a weak signal alone or learn from user traffic.
 */
class ThreatAnalyzer(
    indicators: Collection<ThreatIndicator> = DEFAULT_INDICATORS,
    safeDomains: Collection<String> = DEFAULT_SAFE_DOMAINS,
) {
    private class CompiledIndicator(
        val indicator: ThreatIndicator,
        val domain: String,
        val rank: Int,
    )

    private class FeedSnapshot(
        val revision: Long,
        val feedVersion: Long,
        val expiresAtEpochMillis: Long?,
        val indicatorCount: Int,
        val indicatorsByDomain: Map<String, List<CompiledIndicator>>,
        val safeDomainsSet: Set<String>,
    )

    private val snapshot = AtomicReference(
        compileSnapshot(
            revision = 0L,
            feedVersion = 0L,
            expiresAtEpochMillis = null,
            indicators = indicators,
            safeDomains = safeDomains,
        ),
    )

    val revision: Long
        get() = snapshot.get().revision

    val feedVersion: Long
        get() = snapshot.get().feedVersion

    fun isFeedExpired(nowEpochMillis: Long = System.currentTimeMillis()): Boolean {
        val exp = snapshot.get().expiresAtEpochMillis ?: return false
        return nowEpochMillis >= exp
    }

    /**
     * Atomically verifies and applies a signed threat feed update without interrupting
     * concurrent lookups. Tampered, expired, downgraded, or invalid feeds are rejected.
     */
    fun replaceFeed(
        feed: SignedThreatFeed,
        trustedPublicKey: PublicKey,
        nowEpochMillis: Long = System.currentTimeMillis(),
    ): FeedUpdateResult {
        val current = snapshot.get()
        val verifyFailure = ThreatFeedVerifier.verify(
            feed = feed,
            trustedPublicKey = trustedPublicKey,
            currentFeedVersion = current.feedVersion,
            nowEpochMillis = nowEpochMillis,
        )
        if (verifyFailure != null) {
            return FeedUpdateResult.Rejected(verifyFailure)
        }
        val compiled = try {
            compileSnapshot(
                revision = current.revision + 1L,
                feedVersion = feed.version,
                expiresAtEpochMillis = feed.expiresAtEpochMillis,
                indicators = feed.indicators,
                safeDomains = feed.safeDomains,
            )
        } catch (err: IllegalArgumentException) {
            return FeedUpdateResult.Rejected(err.message ?: "threat_feed_invalid_indicator")
        }
        snapshot.set(compiled)
        return FeedUpdateResult.Applied(
            revision = compiled.revision,
            feedVersion = compiled.feedVersion,
            indicatorCount = compiled.indicatorCount,
            expiresAtEpochMillis = feed.expiresAtEpochMillis,
        )
    }

    fun analyze(domainInput: String): ThreatAssessment {
        val domain = DomainNormalizer.normalize(domainInput)
            ?: return ThreatAssessment(
                domain = null,
                action = PolicyAction.ALLOW,
                riskScore = 0,
                confidence = 0,
                reason = "invalid_domain_input",
            )

        val current = snapshot.get()
        val matched = findBestIndicator(current.indicatorsByDomain, domain)
        if (matched != null) {
            val indicator = matched.indicator
            val signal = ThreatSignal(
                id = indicator.id,
                category = indicator.category,
                confidence = indicator.confidence,
                evidence = indicator.reason,
                source = indicator.source,
            )
            return ThreatAssessment(
                domain = domain,
                action = indicator.action,
                riskScore = indicator.confidence,
                confidence = indicator.confidence,
                reason = indicator.reason,
                indicatorId = indicator.id,
                source = indicator.source,
                signals = listOf(signal),
            )
        }

        if (matchesDomainSet(current.safeDomainsSet, domain)) {
            return ThreatAssessment(
                domain = domain,
                action = PolicyAction.ALLOW,
                riskScore = 0,
                confidence = 100,
                reason = "trusted_domain_allowlist",
            )
        }

        val labels = domain.split('.')
        val signals = buildList {
            if (labels.any { label ->
                    label == "ad" || label == "ads" || label.startsWith("ads-") || label.endsWith("-ads") ||
                        label.contains("advert") || label.contains("banner")
                }) {
                add(
                    ThreatSignal(
                        id = "heuristic_advertising_label",
                        category = ThreatCategory.ADVERTISING,
                        confidence = 35,
                        evidence = "domain_label_contains_advertising_term",
                        source = RuleSource.HEURISTIC,
                    ),
                )
            }
            if (labels.any { label ->
                    listOf("track", "tracker", "tracking", "pixel", "analytics", "telemetry", "metrics", "beacon")
                        .any { term -> label.contains(term) }
                }) {
                add(
                    ThreatSignal(
                        id = "heuristic_tracking_label",
                        category = ThreatCategory.TRACKING,
                        confidence = 30,
                        evidence = "domain_label_contains_tracking_term",
                        source = RuleSource.HEURISTIC,
                    ),
                )
            }
            if (labels.any { label ->
                    PHISHING_LABEL_PATTERNS.any { term -> label.contains(term) }
                }) {
                add(
                    ThreatSignal(
                        id = "heuristic_phishing_lexical_cue",
                        category = ThreatCategory.PHISHING,
                        confidence = 40,
                        evidence = "domain_label_contains_phishing_cue",
                        source = RuleSource.HEURISTIC,
                    ),
                )
            }
        }

        if (signals.isEmpty()) {
            return ThreatAssessment(
                domain = domain,
                action = PolicyAction.ALLOW,
                riskScore = 0,
                confidence = 0,
                reason = "no_threat_signals",
            )
        }

        val strongest = signals.maxBy { it.confidence }
        return ThreatAssessment(
            domain = domain,
            action = PolicyAction.OBSERVE,
            riskScore = signals.sumOf { it.confidence }.coerceAtMost(100),
            confidence = strongest.confidence,
            reason = "heuristic_signals_require_observation",
            source = RuleSource.HEURISTIC,
            signals = signals,
        )
    }

    private fun findBestIndicator(
        byDomain: Map<String, List<CompiledIndicator>>,
        domain: String,
    ): CompiledIndicator? {
        var best: CompiledIndicator? = null
        var idx = 0
        var isExact = true
        while (true) {
            val suffix = if (idx == 0) domain else domain.substring(idx)
            val bucket = byDomain[suffix]
            if (bucket != null) {
                for (candidate in bucket) {
                    if (best != null && candidate.rank >= best.rank) break
                    if (!isExact && !candidate.indicator.includeSubdomains) continue
                    best = candidate
                    break
                }
            }
            val nextDot = domain.indexOf('.', idx)
            if (nextDot < 0) break
            idx = nextDot + 1
            isExact = false
        }
        return best
    }

    private fun matchesDomainSet(domains: Set<String>, domain: String): Boolean {
        if (domains.isEmpty()) return false
        var idx = 0
        while (true) {
            val suffix = if (idx == 0) domain else domain.substring(idx)
            if (suffix in domains) return true
            val nextDot = domain.indexOf('.', idx)
            if (nextDot < 0) break
            idx = nextDot + 1
        }
        return false
    }

    private fun compileSnapshot(
        revision: Long,
        feedVersion: Long,
        expiresAtEpochMillis: Long?,
        indicators: Collection<ThreatIndicator>,
        safeDomains: Collection<String>,
    ): FeedSnapshot {
        require(indicators.map { it.id }.distinct().size == indicators.size) {
            "Threat indicator IDs must be unique"
        }
        val prepared = indicators.map { indicator ->
            require(indicator.id.isNotBlank()) { "Threat indicator ID must not be blank" }
            require(indicator.reason.isNotBlank()) { "Threat indicator reason must not be blank" }
            require(indicator.confidence in 0..100) { "Threat confidence must be between 0 and 100" }
            require(
                indicator.action != PolicyAction.BLOCK ||
                    (indicator.confidence >= MIN_TRUSTED_BLOCK_CONFIDENCE && indicator.source != RuleSource.HEURISTIC),
            ) {
                "Blocking indicators require high-confidence curated provenance"
            }
            indicator to requireNotNull(DomainNormalizer.normalize(indicator.domain)) {
                "Invalid threat indicator domain '${indicator.id}'"
            }
        }.sortedWith(
            compareByDescending<Pair<ThreatIndicator, String>> { it.second.length }
                .thenByDescending { it.first.confidence }
                .thenBy { it.first.id },
        )

        val indexed = HashMap<String, MutableList<CompiledIndicator>>(prepared.size)
        prepared.forEachIndexed { index, (indicator, normalizedDomain) ->
            indexed.getOrPut(normalizedDomain) { ArrayList(1) }
                .add(CompiledIndicator(indicator, normalizedDomain, index))
        }

        val normalizedSafe = safeDomains.mapTo(HashSet(safeDomains.size)) { domain ->
            requireNotNull(DomainNormalizer.normalize(domain)) { "Invalid safe domain '$domain'" }
        }
        return FeedSnapshot(
            revision = revision,
            feedVersion = feedVersion,
            expiresAtEpochMillis = expiresAtEpochMillis,
            indicatorCount = prepared.size,
            indicatorsByDomain = indexed,
            safeDomainsSet = normalizedSafe,
        )
    }

    private companion object {
        const val MIN_TRUSTED_BLOCK_CONFIDENCE = 90

        val PHISHING_LABEL_PATTERNS = listOf(
            "verify-account",
            "login-security",
            "secure-verify",
            "wallet-restore",
            "account-recovery-login",
        )

        val DEFAULT_INDICATORS = listOf(
            ThreatIndicator("ads-doubleclick", "doubleclick.net", category = ThreatCategory.ADVERTISING, confidence = 99, action = PolicyAction.BLOCK, reason = "known_ad_delivery_domain"),
            ThreatIndicator("ads-googlesyndication", "googlesyndication.com", category = ThreatCategory.ADVERTISING, confidence = 99, action = PolicyAction.BLOCK, reason = "known_ad_delivery_domain"),
            ThreatIndicator("ads-googleadservices", "googleadservices.com", category = ThreatCategory.ADVERTISING, confidence = 98, action = PolicyAction.BLOCK, reason = "known_ad_delivery_domain"),
            ThreatIndicator("ads-adnxs", "adnxs.com", category = ThreatCategory.ADVERTISING, confidence = 97, action = PolicyAction.BLOCK, reason = "known_ad_exchange_domain"),
            ThreatIndicator("ads-taboola", "taboola.com", category = ThreatCategory.ADVERTISING, confidence = 96, action = PolicyAction.BLOCK, reason = "known_recommendation_ad_domain"),
            ThreatIndicator("ads-outbrain", "outbrain.com", category = ThreatCategory.ADVERTISING, confidence = 96, action = PolicyAction.BLOCK, reason = "known_recommendation_ad_domain"),
            ThreatIndicator("track-google-analytics", "google-analytics.com", category = ThreatCategory.TRACKING, confidence = 88, action = PolicyAction.OBSERVE, reason = "known_analytics_domain"),
            ThreatIndicator("track-tag-manager", "googletagmanager.com", category = ThreatCategory.TRACKING, confidence = 82, action = PolicyAction.OBSERVE, reason = "known_tag_management_domain"),
            ThreatIndicator("track-facebook-pixel", "pixel.facebook.com", category = ThreatCategory.TRACKING, confidence = 88, action = PolicyAction.OBSERVE, reason = "known_social_tracking_pixel"),
            ThreatIndicator("track-facebook-connect", "connect.facebook.net", category = ThreatCategory.TRACKING, confidence = 82, action = PolicyAction.OBSERVE, reason = "social_sdk_tracking_endpoint"),
        )

        val DEFAULT_SAFE_DOMAINS = listOf(
            "whatsapp.com",
            "whatsapp.net",
            "facebook.com",
            "fbcdn.net",
            "youtube.com",
            "google.com",
            "gstatic.com",
            "googleapis.com",
            "android.com",
        )
    }
}
