package com.firewalldns.engine.dns

import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.PolicyDecision
import com.firewalldns.engine.core.PolicyEngine
import com.firewalldns.engine.core.PolicyRequest

sealed interface DnsEvaluation {
    data class Forward(val question: DnsQuestion, val decision: PolicyDecision) : DnsEvaluation
    data class Blocked(val question: DnsQuestion, val decision: PolicyDecision, val response: ByteArray) : DnsEvaluation
    data class Rejected(val reason: String) : DnsEvaluation
}

/** Connects validated DNS questions to the shared policy engine. */
class DnsPolicyAdapter(private val policyEngine: PolicyEngine) {
    fun evaluate(packet: ByteArray, appPackage: String? = null, nowEpochMillis: Long = System.currentTimeMillis()): DnsEvaluation {
        val question = when (val parsed = DnsMessageParser.parse(packet)) {
            is DnsParseResult.Valid -> parsed.question
            is DnsParseResult.Invalid -> return DnsEvaluation.Rejected(parsed.reason)
        }
        val decision = policyEngine.evaluate(
            PolicyRequest(question.domain, appPackage),
            nowEpochMillis,
        )
        return when (decision.action) {
            PolicyAction.BLOCK -> DnsEvaluation.Blocked(question, decision, nxdomainResponse(question))
            PolicyAction.OBSERVE, PolicyAction.ALLOW -> DnsEvaluation.Forward(question, decision)
        }
    }

    private fun nxdomainResponse(question: DnsQuestion): ByteArray {
        val response = ByteArray(12 + question.wireQuestion.size)
        putU16(response, 0, question.id)
        // QR + preserve RD and CD + NXDOMAIN. RA is not asserted by this local synthesizer.
        val flags = 0x8000 or (question.requestFlags and (0x0100 or 0x0010)) or 0x0003
        putU16(response, 2, flags)
        putU16(response, 4, 1)
        putU16(response, 6, 0)
        putU16(response, 8, 0)
        putU16(response, 10, 0)
        question.wireQuestion.copyInto(response, destinationOffset = 12)
        return response
    }

    private fun putU16(target: ByteArray, offset: Int, value: Int) {
        target[offset] = (value ushr 8).toByte()
        target[offset + 1] = value.toByte()
    }
}
