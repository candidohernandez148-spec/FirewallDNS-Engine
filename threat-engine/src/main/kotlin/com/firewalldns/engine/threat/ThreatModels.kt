package com.firewalldns.engine.threat

import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.RuleSource

enum class ThreatCategory { ADVERTISING, TRACKING, MALWARE, PHISHING, SUSPICIOUS }

data class ThreatIndicator(
    val id: String,
    val domain: String,
    val includeSubdomains: Boolean = true,
    val category: ThreatCategory,
    val confidence: Int,
    val action: PolicyAction,
    val source: RuleSource = RuleSource.BUILTIN,
    val reason: String,
)

data class ThreatSignal(
    val id: String,
    val category: ThreatCategory,
    val confidence: Int,
    val evidence: String,
    val source: RuleSource,
)

data class ThreatAssessment(
    val domain: String?,
    val action: PolicyAction,
    val riskScore: Int,
    val confidence: Int,
    val reason: String,
    val indicatorId: String? = null,
    val source: RuleSource? = null,
    val signals: List<ThreatSignal> = emptyList(),
)

data class SignedThreatFeed(
    val version: Long,
    val publishedAtEpochMillis: Long,
    val expiresAtEpochMillis: Long,
    val indicators: List<ThreatIndicator>,
    val safeDomains: List<String> = emptyList(),
    val signatureBase64: String,
)

sealed interface FeedUpdateResult {
    data class Applied(
        val revision: Long,
        val feedVersion: Long,
        val indicatorCount: Int,
        val expiresAtEpochMillis: Long,
    ) : FeedUpdateResult

    data class Rejected(val reason: String) : FeedUpdateResult
}
