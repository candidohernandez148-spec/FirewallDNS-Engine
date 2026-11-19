package com.firewalldns.engine.core

/** OBSERVE records a signal but does not block the request. */
enum class PolicyAction { BLOCK, OBSERVE, ALLOW }
enum class RuleSource(val precedence: Int) { LEARNED(1), BUILTIN(2), MANAGED(3), USER(4) }

data class PolicyRule(
    val id: String,
    val domain: String,
    val includeSubdomains: Boolean = true,
    val appPackage: String? = null,
    val action: PolicyAction,
    val source: RuleSource,
    val priority: Int = 0,
    val reason: String,
    val enabled: Boolean = true,
    /** Unix epoch milliseconds; null means no expiry. */
    val expiresAtEpochMillis: Long? = null,
)

data class PolicyRequest(val domain: String, val appPackage: String? = null)

data class PolicyDecision(
    val action: PolicyAction,
    val reason: String,
    val ruleId: String? = null,
    val source: RuleSource? = null,
    val policyRevision: Long = 0,
    val expiresAtEpochMillis: Long? = null,
)
