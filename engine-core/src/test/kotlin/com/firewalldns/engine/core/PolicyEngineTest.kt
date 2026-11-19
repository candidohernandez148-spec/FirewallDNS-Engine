package com.firewalldns.engine.core

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull

class PolicyEngineTest {
    @Test fun defaultsToAllowWhenNoRuleMatches() {
        val result = PolicyEngine().evaluate(PolicyRequest("example.com"), 1)
        assertEquals(PolicyAction.ALLOW, result.action)
        assertEquals("no_matching_rule", result.reason)
        assertNull(result.ruleId)
    }

    @Test fun blockMatchesSubdomainsWithoutSuffixSpoofing() {
        val engine = PolicyEngine(listOf(rule("tracker", "ads.example.com", PolicyAction.BLOCK)))
        assertEquals(PolicyAction.BLOCK, engine.evaluate(PolicyRequest("img.ads.example.com"), 1).action)
        assertEquals(PolicyAction.ALLOW, engine.evaluate(PolicyRequest("notexample.com"), 1).action)
    }

    @Test fun exactRuleDoesNotMatchSubdomains() {
        val engine = PolicyEngine(listOf(rule("exact", "ads.example.com", PolicyAction.BLOCK, exact = true)))
        assertEquals(PolicyAction.BLOCK, engine.evaluate(PolicyRequest("ads.example.com"), 1).action)
        assertEquals(PolicyAction.ALLOW, engine.evaluate(PolicyRequest("img.ads.example.com"), 1).action)
    }

    @Test fun observeRemainsNonBlockingAndExplainable() {
        val result = PolicyEngine(listOf(rule("watch", "watch.example", PolicyAction.OBSERVE)))
            .evaluate(PolicyRequest("watch.example"), 1)
        assertEquals(PolicyAction.OBSERVE, result.action)
        assertEquals("test_rule", result.reason)
    }

    @Test fun higherPriorityWinsRegardlessOfSource() {
        val engine = PolicyEngine(listOf(
            rule("builtin", "example.com", PolicyAction.BLOCK, source = RuleSource.BUILTIN, priority = 10),
            rule("user-allow", "example.com", PolicyAction.ALLOW, source = RuleSource.USER, priority = 20),
        ))
        val result = engine.evaluate(PolicyRequest("example.com"), 1)
        assertEquals(PolicyAction.ALLOW, result.action)
        assertEquals("user-allow", result.ruleId)
    }

    @Test fun userSourceWinsAtEqualPriority() {
        val engine = PolicyEngine(listOf(
            rule("learned", "example.com", PolicyAction.BLOCK, source = RuleSource.LEARNED),
            rule("user", "example.com", PolicyAction.ALLOW, source = RuleSource.USER),
        ))
        assertEquals("user", engine.evaluate(PolicyRequest("example.com"), 1).ruleId)
    }

    @Test fun appScopedRuleOnlyMatchesKnownMatchingPackage() {
        val engine = PolicyEngine(listOf(rule(
            "app-rule", "example.com", PolicyAction.BLOCK, appPackage = "com.example.app",
        )))
        assertEquals(PolicyAction.BLOCK, engine.evaluate(PolicyRequest("example.com", "com.example.app"), 1).action)
        assertEquals(PolicyAction.ALLOW, engine.evaluate(PolicyRequest("example.com", "com.other.app"), 1).action)
        assertEquals(PolicyAction.ALLOW, engine.evaluate(PolicyRequest("example.com"), 1).action)
    }

    @Test fun expiredAndDisabledRulesAreIgnored() {
        val engine = PolicyEngine(listOf(
            rule("expired", "expired.example", PolicyAction.BLOCK, expiry = 10),
            rule("disabled", "disabled.example", PolicyAction.BLOCK, enabled = false),
        ))
        assertEquals(PolicyAction.ALLOW, engine.evaluate(PolicyRequest("expired.example"), 10).action)
        assertEquals(PolicyAction.ALLOW, engine.evaluate(PolicyRequest("disabled.example"), 1).action)
    }

    @Test fun invalidInputHasExplicitFailOpenReason() {
        val result = PolicyEngine().evaluate(PolicyRequest("bad domain"), 1)
        assertEquals(PolicyAction.ALLOW, result.action)
        assertEquals("invalid_domain_input", result.reason)
    }

    @Test fun invalidReplacementDoesNotReplaceActiveSnapshot() {
        val engine = PolicyEngine(listOf(rule("valid", "safe.example", PolicyAction.BLOCK)))
        assertFailsWith<IllegalArgumentException> {
            engine.replaceRules(listOf(rule("invalid", "not a valid domain", PolicyAction.BLOCK)))
        }
        assertEquals(PolicyAction.BLOCK, engine.evaluate(PolicyRequest("safe.example"), 1).action)
    }

    @Test fun duplicateIdsAreRejected() {
        assertFailsWith<IllegalArgumentException> {
            PolicyEngine(listOf(
                rule("duplicate", "a.example", PolicyAction.BLOCK),
                rule("duplicate", "b.example", PolicyAction.ALLOW),
            ))
        }
    }

    @Test fun normalizesCaseTrailingDotAndIdn() {
        assertEquals("example.com", DomainNormalizer.normalize("EXAMPLE.COM."))
        assertEquals("xn--bcher-kva.example", DomainNormalizer.normalize("bücher.example"))
        assertEquals("_sip._tcp.example.com", DomainNormalizer.normalize("_SIP._TCP.EXAMPLE.COM."))
    }

    @Test fun policyRevisionAdvancesOnlyAfterValidReplacement() {
        val engine = PolicyEngine(listOf(rule("first", "example.com", PolicyAction.BLOCK)))
        val initialRevision = engine.revision
        assertEquals(initialRevision, engine.evaluate(PolicyRequest("example.com"), 1).policyRevision)

        assertFailsWith<IllegalArgumentException> {
            engine.replaceRules(listOf(rule("invalid", "not a valid domain", PolicyAction.BLOCK)))
        }
        assertEquals(initialRevision, engine.revision)

        engine.replaceRules(listOf(rule("second", "example.com", PolicyAction.ALLOW)))
        assertEquals(initialRevision + 1, engine.revision)
        assertEquals(initialRevision + 1, engine.evaluate(PolicyRequest("example.com"), 1).policyRevision)
    }

    private fun rule(
        id: String, domain: String, action: PolicyAction,
        exact: Boolean = false, appPackage: String? = null,
        source: RuleSource = RuleSource.MANAGED, priority: Int = 0,
        expiry: Long? = null, enabled: Boolean = true,
    ) = PolicyRule(
        id = id, domain = domain, includeSubdomains = !exact, appPackage = appPackage,
        action = action, source = source, priority = priority, reason = "test_rule",
        enabled = enabled, expiresAtEpochMillis = expiry,
    )
}
