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
