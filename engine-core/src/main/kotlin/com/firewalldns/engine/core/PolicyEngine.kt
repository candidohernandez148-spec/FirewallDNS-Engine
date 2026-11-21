package com.firewalldns.engine.core

import java.util.concurrent.atomic.AtomicReference

/**
 * In-memory policy evaluator. Rule replacement is atomic; evaluations read an
 * immutable snapshot and perform no disk/network I/O or lock acquisition.
 */
class PolicyEngine(initialRules: Collection<PolicyRule> = emptyList()) {
    private data class Snapshot(
        val revision: Long,
        val rulesByDomain: Map<String, List<CompiledRule>>,
    )

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

        var best: CompiledRule? = null
        var idx = 0
        var isExact = true
        while (true) {
            val suffix = if (idx == 0) domain else domain.substring(idx)
            val bucket = current.rulesByDomain[suffix]
            if (bucket != null) {
                for (candidate in bucket) {
                    if (best != null && candidate.rank >= best.rank) break
                    if (!isExact && !candidate.rule.includeSubdomains) continue
                    if (!candidate.rule.enabled) continue
                    val expiry = candidate.rule.expiresAtEpochMillis
                    if (expiry != null && expiry <= nowEpochMillis) continue
                    val requiredPackage = candidate.rule.appPackage
                    if (requiredPackage != null && requiredPackage != request.appPackage) continue
                    best = candidate
                    break
                }
            }
            val nextDot = domain.indexOf('.', idx)
            if (nextDot < 0) break
            idx = nextDot + 1
            isExact = false
        }

        return best?.let {
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

    private class CompiledRule(
        val rule: PolicyRule,
        val normalizedDomain: String,
        val rank: Int,
    )

    private fun compile(input: Collection<PolicyRule>): Map<String, List<CompiledRule>> {
        require(input.map { it.id }.distinct().size == input.size) { "Policy rule IDs must be unique" }
        val prepared = input.map { rule ->
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
            rule to normalizedDomain
        }.sortedWith(
            compareByDescending<Pair<PolicyRule, String>> { it.first.priority }
                .thenByDescending { it.first.source.precedence }
                .thenByDescending { it.second.length }
                .thenByDescending { !it.first.includeSubdomains }
                .thenByDescending { it.first.appPackage != null }
                .thenBy { it.first.id },
        )

        val indexed = HashMap<String, MutableList<CompiledRule>>(prepared.size)
        prepared.forEachIndexed { index, (rule, normalizedDomain) ->
            indexed.getOrPut(normalizedDomain) { ArrayList(1) }
                .add(CompiledRule(rule, normalizedDomain, index))
        }
        return indexed
    }

    private companion object {
        const val MIN_PRIORITY = -100_000
        const val MAX_PRIORITY = 100_000
        val APP_PACKAGE_PATTERN = Regex("[A-Za-z_][A-Za-z0-9_]*(\\.[A-Za-z_][A-Za-z0-9_]*)+")
    }
}
