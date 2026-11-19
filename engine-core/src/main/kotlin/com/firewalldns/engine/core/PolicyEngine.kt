package com.firewalldns.engine.core

import java.util.concurrent.atomic.AtomicReference

/**
 * In-memory policy evaluator. Rule replacement is atomic; evaluations read an
 * immutable snapshot and perform no disk/network I/O or lock acquisition.
 */
class PolicyEngine(initialRules: Collection<PolicyRule> = emptyList()) {
    private val rules = AtomicReference(compile(initialRules))

    /** Invalid updates are rejected as a whole; the active snapshot is retained. */
    fun replaceRules(newRules: Collection<PolicyRule>) {
        rules.set(compile(newRules))
    }

    /** The explicit time parameter makes expiry behavior deterministic in tests. */
    fun evaluate(
        request: PolicyRequest,
        nowEpochMillis: Long = System.currentTimeMillis(),
    ): PolicyDecision {
        val domain = DomainNormalizer.normalize(request.domain)
            ?: return PolicyDecision(PolicyAction.ALLOW, "invalid_domain_input")

        val winner = rules.get()
            .asSequence()
            .filter { it.rule.enabled }
            .filter { it.rule.expiresAtEpochMillis?.let { expiry -> expiry > nowEpochMillis } ?: true }
            .filter { compiled ->
                val requiredPackage = compiled.rule.appPackage
                requiredPackage == null || requiredPackage == request.appPackage
            }
            .firstOrNull { it.matches(domain) }

        return winner?.let {
            PolicyDecision(it.rule.action, it.rule.reason, it.rule.id, it.rule.source)
        } ?: PolicyDecision(PolicyAction.ALLOW, "no_matching_rule")
    }

    private data class CompiledRule(
        val rule: PolicyRule,
        val normalizedDomain: String,
        val specificity: Int,
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
            CompiledRule(
                rule,
                normalizedDomain,
                (if (rule.includeSubdomains) 0 else 1) + (if (rule.appPackage != null) 1 else 0),
            )
        }
        return compiled.sortedWith(
            compareByDescending<CompiledRule> { it.rule.priority }
                .thenByDescending { it.rule.source.precedence }
                .thenByDescending { it.specificity }
                .thenBy { it.rule.id },
        )
    }

    private companion object {
        const val MIN_PRIORITY = -100_000
        const val MAX_PRIORITY = 100_000
        val APP_PACKAGE_PATTERN = Regex("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+")
    }
}
