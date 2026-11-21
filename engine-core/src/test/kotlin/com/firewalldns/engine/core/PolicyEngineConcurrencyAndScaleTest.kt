package com.firewalldns.engine.core

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference

class PolicyEngineConcurrencyAndScaleTest {

    @Test
    fun indexedLookupPreservesExactPrecedenceSubdomainExpiryAndAppScope() {
        val now = 1_000_000L
        val rules = listOf(
            PolicyRule(
                id = "builtin-broad",
                domain = "example.com",
                includeSubdomains = true,
                action = PolicyAction.BLOCK,
                source = RuleSource.BUILTIN,
                priority = 0,
                reason = "builtin_broad",
            ),
            PolicyRule(
                id = "user-exact-allow",
                domain = "api.ads.example.com",
                includeSubdomains = false,
                action = PolicyAction.ALLOW,
                source = RuleSource.USER,
                priority = 0,
                reason = "user_exact_allow",
            ),
            PolicyRule(
                id = "app-block-sub",
                domain = "ads.example.com",
                includeSubdomains = true,
                appPackage = "com.test.browser",
                action = PolicyAction.BLOCK,
                source = RuleSource.MANAGED,
                priority = 10,
                reason = "app_specific_block",
            ),
            PolicyRule(
                id = "expired-allow",
                domain = "expired.example.com",
                action = PolicyAction.ALLOW,
                source = RuleSource.USER,
                priority = 100,
                reason = "expired_rule",
                expiresAtEpochMillis = now - 1L,
            ),
            PolicyRule(
                id = "disabled-allow",
                domain = "disabled.example.com",
                action = PolicyAction.ALLOW,
                source = RuleSource.USER,
                priority = 100,
                reason = "disabled_rule",
                enabled = false,
            ),
        )
        val engine = PolicyEngine(rules)

        // Exact rule beats managed priority-10 rule only when priority doesn't override; here priority 10 > 0
        val appBlocked = engine.evaluate(PolicyRequest("api.ads.example.com", "com.test.browser"), now)
        assertEquals(PolicyAction.BLOCK, appBlocked.action)
        assertEquals("app-block-sub", appBlocked.ruleId)

        // Without matching appPackage, user-exact-allow wins over builtin-broad
        val otherApp = engine.evaluate(PolicyRequest("api.ads.example.com", "com.other.app"), now)
        assertEquals(PolicyAction.ALLOW, otherApp.action)
        assertEquals("user-exact-allow", otherApp.ruleId)

        // Exact-only rule does not match deeper subdomain
        val deeper = engine.evaluate(PolicyRequest("v2.api.ads.example.com", "com.other.app"), now)
        assertEquals(PolicyAction.BLOCK, deeper.action)
        assertEquals("builtin-broad", deeper.ruleId)

        // Expired & disabled rules fall back to parent rule
        val expired = engine.evaluate(PolicyRequest("expired.example.com"), now)
        assertEquals("builtin-broad", expired.ruleId)
        val disabled = engine.evaluate(PolicyRequest("disabled.example.com"), now)
        assertEquals("builtin-broad", disabled.ruleId)
    }

    @Test
    fun handlesLargeRulesetsAndConcurrentAtomicReplacementsSafely() {
        val largeRules = (0 until 20_000).map { i ->
            PolicyRule(
                id = "r-$i",
                domain = "tracker-$i.adnet.example",
                action = PolicyAction.BLOCK,
                source = RuleSource.MANAGED,
                reason = "bulk_block",
            )
        }
        val engine = PolicyEngine(largeRules)

        val startNanos = System.nanoTime()
        repeat(2_000) { i ->
            val idx = i % 20_000
            val hit = engine.evaluate(PolicyRequest("sub.tracker-$idx.adnet.example"))
            assertEquals(PolicyAction.BLOCK, hit.action)
            val miss = engine.evaluate(PolicyRequest("safe-$idx.clean.example"))
            assertEquals(PolicyAction.ALLOW, miss.action)
        }
        val elapsedMillis = (System.nanoTime() - startNanos) / 1_000_000L
        assertTrue(elapsedMillis < 2_000L, "Expected 4000 indexed evaluations across 20k rules < 2000ms, took ${elapsedMillis}ms")

        val pool = Executors.newFixedThreadPool(5)
        val stop = AtomicBoolean(false)
        val error = AtomicReference<Throwable?>(null)
        val ready = CountDownLatch(5)

        val writer = pool.submit {
            ready.countDown()
            ready.await()
            try {
                for (rev in 1..40) {
                    engine.replaceRules(
                        listOf(
                            PolicyRule(
                                id = "dyn-$rev",
                                domain = "dynamic.example.com",
                                action = if (rev % 2 == 0) PolicyAction.BLOCK else PolicyAction.ALLOW,
                                source = RuleSource.USER,
                                reason = "rev_$rev",
                            ),
                        ),
                    )
                }
            } catch (t: Throwable) {
                error.compareAndSet(null, t)
            } finally {
                stop.set(true)
            }
        }

        repeat(4) {
            pool.submit {
                ready.countDown()
                ready.await()
                try {
                    while (!stop.get()) {
                        val decision = engine.evaluate(PolicyRequest("sub.dynamic.example.com"))
                        assertTrue(decision.policyRevision >= 0L)
                    }
                } catch (t: Throwable) {
                    error.compareAndSet(null, t)
                }
            }
        }

        writer.get(10, TimeUnit.SECONDS)
        pool.shutdown()
        assertTrue(pool.awaitTermination(10, TimeUnit.SECONDS))
        assertEquals(null, error.get())
        assertEquals(40L, engine.revision)
    }
}
