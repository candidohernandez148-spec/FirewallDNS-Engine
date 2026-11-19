package com.firewalldns.engine.core

import java.util.concurrent.atomic.AtomicReference

/**
 * In-memory policy evaluator. Rule replacement is atomic; evaluations read an
 * immutable snapshot and perform no disk/network I/O or lock acquisition.
 */
class PolicyEngine(initialRules: Collection<PolicyRule> = emptyList()) {
    private data class Snapshot(val revision: Long, val rules: List<CompiledRule>)

    private val snapshot = AtomicReference(Snapshot(0, compile(initialRules)))

    /** Monotonically advances after each successfully published ruleset. */
    val revision: Long
        get() = snapshot.get().revision

    /** Invalid updates are rejected as a whole; the active snapshot is retained. */
    fun replaceRules(newRules: Collection<PolicyRule>) {
        val compiled = compile(newRules)
        snapshot.updateAndGet { current -> Snapshot(current.revision + 1, compiled) }
    }

    /** The explicit time parameter makes expiry behavior deterministic in tests. */
    fun evaluate(
        request: PolicyRequest,
        nowEpochMillis: Long = System.currentTimeMillis(),
    ): PolicyDecision {
        val current = snapshot.get()
        val domain = DomainNormalizer.normalize(request.domain)
            ?: return PolicyDecision(
                action = PolicyAction.ALLOW,
                reason = "invalid_domain_input",
                policyRevision = current.revision,
            )

        val winner = current.rules
            .asSequence()
            .filter { it.rule.enabled }
            .filter { it.rule.expiresAtEpochMillis?.let { expiry -> expiry > nowEpochMillis } ?: true }
            .filter { compiled ->
                val requiredPackage = compiled.rule.appPackage
                requiredPackage == null || requiredPackage == request.appPackage
            }
            .firstOrNull { it.matches(domain) }

        return winner?.let {
            PolicyDecision(
                action = it.rule.action,
                reason = it.rule.reason,
                ruleId = it.rule.id,
                source = it.rule.source,
                policyRevision = current.revision,
                expiresAtEpochMillis = it.rule.expiresAtEpochMillis,
            )
        } ?: PolicyDecision(
            action = PolicyAction.ALLOW,
            reason = "no_matching_rule",
            policyRevision = current.revision,
        )
    }

    private data class CompiledRule(
        val rule: PolicyRule,
        val normalizedDomain: String,
    ) {
        fun matches(domain: String): Boolean =
            if (rule.includeSubdomains) domain == normalizedDomain || domain.endsWith(".$normalizedDomain")
            else domain == normalizedDomain
    }

    private fun compile(input: Collection<PolicyRule>): List<CompiledRule> {
        require(input.map { it.id }.distinct().size == input.size) { "Policy rule IDs must be unique" }
        val compiled = input.map { rule ->
            require(rule.id.isNotBlank()) { "Policy rule ID must not be blank" }
            require(rule.reason.isNotBlank()) { "Policy rule reason must not be blank" }
            require(rule.source != RuleSource.HEURISTIC || rule.action != PolicyAction.BLOCK) {
                "Heuristic policy rules must never block"
            }
            require(rule.priority in MIN_PRIORITY..MAX_PRIORITY) {
                "Policy rule priority must be between ${MIN_PRIORITY} and ${MAX_PRIORITY}"
            }
            val normalizedDomain = requireNotNull(DomainNormalizer.normalize(rule.domain)) {
                "Invalid domain in policy rule '${rule.id}'"
            }
            rule.appPackage?.let { packageName ->
                require(APP_PACKAGE_PATTERN.matches(packageName)) {
                    "Invalid Android package name in policy rule '${rule.id}'"
                }
            }
            CompiledRule(rule, normalizedDomain)
        }
        return compiled.sortedWith(
            compareByDescending<CompiledRule> { it.rule.priority }
                .thenByDescending { it.rule.source.precedence }
                .thenByDescending { it.normalizedDomain.length }
                .thenByDescending { !it.rule.includeSubdomains }
                .thenByDescending { it.rule.appPackage != null }
                .thenBy { it.rule.id },
        )
    }

    private companion object {
        const val MIN_PRIORITY = -100_000
        const val MAX_PRIORITY = 100_000
        val APP_PACKAGE_PATTERN = Regex("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+")
    }
}
