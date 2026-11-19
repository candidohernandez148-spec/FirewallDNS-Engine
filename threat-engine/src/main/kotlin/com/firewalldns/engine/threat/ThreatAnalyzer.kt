package com.firewalldns.engine.threat

import com.firewalldns.engine.core.DomainNormalizer
import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.RuleSource

/**
 * Local, explainable domain reputation. Trusted indicators may block; lexical
 * heuristics only OBSERVE and therefore never block on a weak signal alone.
 */
class ThreatAnalyzer(
    indicators: Collection<ThreatIndicator> = DEFAULT_INDICATORS,
    safeDomains: Collection<String> = DEFAULT_SAFE_DOMAINS,
) {
    private data class CompiledIndicator(val indicator: ThreatIndicator, val domain: String)

    private val compiledIndicators: List<CompiledIndicator>
    private val normalizedSafeDomains: List<String>

    init {
        require(indicators.map { it.id }.distinct().size == indicators.size) {
            "Threat indicator IDs must be unique"
        }
        compiledIndicators = indicators.map { indicator ->
            require(indicator.id.isNotBlank()) { "Threat indicator ID must not be blank" }
            require(indicator.reason.isNotBlank()) { "Threat indicator reason must not be blank" }
            require(indicator.confidence in 0..100) { "Threat confidence must be between 0 and 100" }
            require(indicator.action != PolicyAction.BLOCK ||
                (indicator.confidence >= MIN_TRUSTED_BLOCK_CONFIDENCE && indicator.source != RuleSource.HEURISTIC)) {
                "Blocking indicators require high-confidence curated provenance"
            }
            CompiledIndicator(
                indicator,
                requireNotNull(DomainNormalizer.normalize(indicator.domain)) {
                    "Invalid threat indicator domain '${indicator.id}'"
                },
            )
        }.sortedWith(
            compareByDescending<CompiledIndicator> { it.domain.length }
                .thenByDescending { it.indicator.confidence }
                .thenBy { it.indicator.id },
        )
        normalizedSafeDomains = safeDomains.map { domain ->
            requireNotNull(DomainNormalizer.normalize(domain)) { "Invalid safe domain '$domain'" }
        }
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

        val matched = compiledIndicators.firstOrNull { compiled ->
            if (compiled.indicator.includeSubdomains) {
                domain == compiled.domain || domain.endsWith(".${compiled.domain}")
            } else {
                domain == compiled.domain
            }
        }
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

        if (normalizedSafeDomains.any { domain == it || domain.endsWith(".$it") }) {
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
                    label == "ad" || label == "ads" || label.startsWith("ads-") || label.endsWith("-ads") || label.contains("advert") || label.contains("banner")
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

    private companion object {
        const val MIN_TRUSTED_BLOCK_CONFIDENCE = 90

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
