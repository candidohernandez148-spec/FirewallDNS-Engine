package com.firewalldns.engine.runtime

import com.firewalldns.engine.core.PolicyEngine
import com.firewalldns.engine.core.PolicyRule
import com.firewalldns.engine.dns.DnsEvaluation
import com.firewalldns.engine.dns.DnsPolicyAdapter
import com.firewalldns.engine.monitor.EngineEvent
import com.firewalldns.engine.monitor.EngineMetricsSnapshot
import com.firewalldns.engine.monitor.EngineMonitor
import com.firewalldns.engine.threat.FeedUpdateResult
import com.firewalldns.engine.threat.SignedThreatFeed
import com.firewalldns.engine.threat.ThreatAnalyzer
import java.security.PublicKey

/**
 * Single public entry point for the FirewallDNS decision engine.
 */
class EngineRuntime(
    initialRules: Collection<PolicyRule> = emptyList(),
    private val threatAnalyzer: ThreatAnalyzer = ThreatAnalyzer(),
    val monitor: EngineMonitor = EngineMonitor(),
) {
    private val policyEngine = PolicyEngine(initialRules)
    private val dnsAdapter = DnsPolicyAdapter(
        policyEngine = policyEngine,
        threatAnalyzer = threatAnalyzer,
        monitor = monitor,
    )

    val policyRevision: Long
        get() = policyEngine.revision

    val threatRevision: Long
        get() = threatAnalyzer.revision

    val threatFeedVersion: Long
        get() = threatAnalyzer.feedVersion

    fun isThreatFeedExpired(nowEpochMillis: Long = System.currentTimeMillis()): Boolean =
        threatAnalyzer.isFeedExpired(nowEpochMillis)

    /** Atomically replaces the complete rules snapshot. */
    fun replaceRules(rules: Collection<PolicyRule>) {
        policyEngine.replaceRules(rules)
    }

    /** Atomically verifies and applies a signed threat feed update. */
    fun replaceThreatFeed(
        feed: SignedThreatFeed,
        trustedPublicKey: PublicKey,
        nowEpochMillis: Long = System.currentTimeMillis(),
    ): FeedUpdateResult = threatAnalyzer.replaceFeed(feed, trustedPublicKey, nowEpochMillis)

    /** Evaluates one DNS packet; OBSERVE always forwards and BLOCK synthesizes NXDOMAIN. */
    fun evaluateDns(
        packet: ByteArray,
        appPackage: String? = null,
        nowEpochMillis: Long = System.currentTimeMillis(),
    ): DnsEvaluation = dnsAdapter.evaluate(packet, appPackage, nowEpochMillis)

    /** Drains a bounded number of local monitor events for the host UI/storage adapter. */
    fun drainEvents(maxCount: Int): List<EngineEvent> = monitor.drainEvents(maxCount)

    fun metrics(): EngineMetricsSnapshot = monitor.snapshot()
}
