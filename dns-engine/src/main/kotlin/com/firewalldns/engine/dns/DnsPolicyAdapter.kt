package com.firewalldns.engine.dns

import com.firewalldns.engine.core.DomainNormalizer
import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.PolicyDecision
import com.firewalldns.engine.core.PolicyEngine
import com.firewalldns.engine.core.PolicyRequest
import com.firewalldns.engine.threat.ThreatAnalyzer
import com.firewalldns.engine.monitor.EngineMonitor

sealed interface DnsEvaluation {
    data class Forward(val question: DnsQuestion, val decision: PolicyDecision) : DnsEvaluation
    data class Blocked(val question: DnsQuestion, val decision: PolicyDecision, val response: ByteArray) : DnsEvaluation
    data class Rejected(val reason: String) : DnsEvaluation
}

/** Connects validated DNS questions to the shared policy engine. */
class DnsPolicyAdapter(
    private val policyEngine: PolicyEngine,
    private val decisionCache: DnsDecisionCache = DnsDecisionCache(),
    private val threatAnalyzer: ThreatAnalyzer = ThreatAnalyzer(),
    val monitor: EngineMonitor = EngineMonitor(),
) {
    fun evaluate(packet: ByteArray, appPackage: String? = null, nowEpochMillis: Long = System.currentTimeMillis()): DnsEvaluation {
        val question = when (val parsed = DnsMessageParser.parse(packet)) {
            is DnsParseResult.Valid -> parsed.question
            is DnsParseResult.Invalid -> {
                monitor.recordRejected(parsed.reason, nowEpochMillis)
                return DnsEvaluation.Rejected(parsed.reason)
            }
        }
        if (question.dnsClass != 1) {
            val decision = PolicyDecision(PolicyAction.ALLOW, "dns_class_not_filtered")
            monitor.recordDecision(question.domain, appPackage, decision, nowEpochMillis)
            return DnsEvaluation.Forward(question, decision)
        }
        val normalizedDomain = DomainNormalizer.normalize(question.domain)
            ?: run {
                monitor.recordRejected("dns_qname_invalid_hostname", nowEpochMillis)
                return DnsEvaluation.Rejected("dns_qname_invalid_hostname")
            }
        val cacheKey = DnsDecisionCacheKey(normalizedDomain, appPackage, policyEngine.revision)
        val cachedDecision = decisionCache.get(cacheKey, nowEpochMillis)
        if (cachedDecision != null) monitor.recordCacheHit() else monitor.recordCacheMiss()
        val decision = cachedDecision ?: run {
            val policyDecision = policyEngine.evaluate(
                PolicyRequest(normalizedDomain, appPackage),
                nowEpochMillis,
            )
            val effectiveDecision = if (policyDecision.reason == "no_matching_rule") {
                val assessment = threatAnalyzer.analyze(normalizedDomain)
                policyDecision.copy(
                    action = assessment.action,
                    reason = assessment.reason,
                    ruleId = assessment.indicatorId,
                    source = assessment.source,
                )
            } else {
                policyDecision
            }
            decisionCache.put(
                DnsDecisionCacheKey(normalizedDomain, appPackage, effectiveDecision.policyRevision),
                effectiveDecision,
                nowEpochMillis,
            )
            effectiveDecision
        }
        monitor.recordDecision(normalizedDomain, appPackage, decision, nowEpochMillis)
        return when (decision.action) {
            PolicyAction.BLOCK -> DnsEvaluation.Blocked(question, decision, nxdomainResponse(question))
            PolicyAction.OBSERVE, PolicyAction.ALLOW -> DnsEvaluation.Forward(question, decision)
        }
    }

    private fun nxdomainResponse(question: DnsQuestion): ByteArray {
        val opt = question.ednsUdpPayloadSize?.let { payloadSize ->
            byteArrayOf(
                0, 0, 41,
                (payloadSize ushr 8).toByte(), payloadSize.toByte(),
                0, 0, if (question.ednsDnssecOk) 0x80.toByte() else 0, 0,
                0, 0,
            )
        } ?: byteArrayOf()
        val response = ByteArray(12 + question.wireQuestion.size + opt.size)
        putU16(response, 0, question.id)
        // QR + preserve RD and CD + NXDOMAIN. RA is not asserted by this local synthesizer.
        val flags = 0x8000 or (question.requestFlags and (0x0100 or 0x0010)) or 0x0003
        putU16(response, 2, flags)
        putU16(response, 4, 1)
        putU16(response, 6, 0)
        putU16(response, 8, 0)
        putU16(response, 10, if (opt.isEmpty()) 0 else 1)
        question.wireQuestion.copyInto(response, destinationOffset = 12)
        if (opt.isNotEmpty()) opt.copyInto(response, destinationOffset = 12 + question.wireQuestion.size)
        return response
    }

    private fun putU16(target: ByteArray, offset: Int, value: Int) {
        target[offset] = (value ushr 8).toByte()
        target[offset + 1] = value.toByte()
    }
}
