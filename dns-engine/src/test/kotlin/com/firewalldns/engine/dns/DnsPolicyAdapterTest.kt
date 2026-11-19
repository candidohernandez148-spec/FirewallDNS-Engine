package com.firewalldns.engine.dns

import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.PolicyEngine
import com.firewalldns.engine.core.PolicyRule
import com.firewalldns.engine.core.RuleSource
import com.firewalldns.engine.monitor.EngineMonitor
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs

class DnsPolicyAdapterTest {
    @Test fun blockedQuestionProducesValidNxdomainWithOriginalIdAndQuestion() {
        val request = query("ads.example.com")
        val adapter = DnsPolicyAdapter(PolicyEngine(listOf(rule("ads.example.com", PolicyAction.BLOCK))))
        val result = assertIs<DnsEvaluation.Blocked>(adapter.evaluate(request))
        assertEquals(0x1234, u16(result.response, 0))
        assertEquals(0x8103, u16(result.response, 2)) // QR + preserved RD + NXDOMAIN
        assertEquals(1, u16(result.response, 4))
        assertContentEquals(request.copyOfRange(12, request.size), result.response.copyOfRange(12, result.response.size))
    }

    @Test fun publishesDecisionAndCacheMetricsToMonitor() {
        val monitor = EngineMonitor(captureDomains = true)
        val adapter = DnsPolicyAdapter(PolicyEngine(), monitor = monitor)
        adapter.evaluate(query("ads.doubleclick.net"), nowEpochMillis = 1)
        adapter.evaluate(query("ads.doubleclick.net"), nowEpochMillis = 2)

        val metrics = monitor.snapshot()
        assertEquals(2, metrics.decisions)
        assertEquals(2, metrics.blocked)
        assertEquals(1, metrics.cacheMisses)
        assertEquals(1, metrics.cacheHits)
        assertEquals("ads.doubleclick.net", monitor.pollEvent()?.domain)
    }

    @Test fun malformedDnsIsCountedAsRejectedByMonitor() {
        val monitor = EngineMonitor()
        val result = DnsPolicyAdapter(PolicyEngine(), monitor = monitor)
            .evaluate(byteArrayOf(1, 2, 3), nowEpochMillis = 10)
        assertIs<DnsEvaluation.Rejected>(result)
        assertEquals(1, monitor.snapshot().rejected)
    }

    @Test fun builtInThreatIntelligenceBlocksKnownAdDeliveryDomain() {
        val result = assertIs<DnsEvaluation.Blocked>(
            DnsPolicyAdapter(PolicyEngine()).evaluate(query("ads.doubleclick.net")),
        )
        assertEquals("ads-doubleclick", result.decision.ruleId)
        assertEquals(PolicyAction.BLOCK, result.decision.action)
    }

    @Test fun weakDomainHeuristicsOnlyObserveAndTrustedDomainsAreAllowed() {
        val adapter = DnsPolicyAdapter(PolicyEngine())
        val heuristic = assertIs<DnsEvaluation.Forward>(adapter.evaluate(query("ads-tracker.example.com")))
        assertEquals(PolicyAction.OBSERVE, heuristic.decision.action)

        val trusted = assertIs<DnsEvaluation.Forward>(adapter.evaluate(query("metrics.youtube.com")))
        assertEquals(PolicyAction.ALLOW, trusted.decision.action)
        assertEquals("trusted_domain_allowlist", trusted.decision.reason)
    }

    @Test fun explicitUserAllowOverridesBuiltInThreatIndicator() {
        val allowRule = PolicyRule(
            id = "user-allow-doubleclick",
            domain = "doubleclick.net",
            action = PolicyAction.ALLOW,
            source = RuleSource.USER,
            reason = "user_explicit_allow",
        )
        val result = assertIs<DnsEvaluation.Forward>(
            DnsPolicyAdapter(PolicyEngine(listOf(allowRule))).evaluate(query("ads.doubleclick.net")),
        )
        assertEquals("user_explicit_allow", result.decision.reason)
    }

    @Test fun policyReplacementCannotReuseStaleCachedDecision() {
        val engine = PolicyEngine(listOf(rule("ads.example.com", PolicyAction.BLOCK)))
        val adapter = DnsPolicyAdapter(engine, DnsDecisionCache())
        assertIs<DnsEvaluation.Blocked>(adapter.evaluate(query("ads.example.com"), nowEpochMillis = 1))

        engine.replaceRules(listOf(rule("ads.example.com", PolicyAction.ALLOW)))
        val afterUpdate = assertIs<DnsEvaluation.Forward>(
            adapter.evaluate(query("ads.example.com"), nowEpochMillis = 2),
        )
        assertEquals(PolicyAction.ALLOW, afterUpdate.decision.action)
    }

    @Test fun observeForwardsAndDoesNotSynthesizeBlock() {
        val adapter = DnsPolicyAdapter(PolicyEngine(listOf(rule("watch.example.com", PolicyAction.OBSERVE))))
        val result = assertIs<DnsEvaluation.Forward>(adapter.evaluate(query("watch.example.com")))
        assertEquals(PolicyAction.OBSERVE, result.decision.action)
    }

    @Test fun unmatchedDomainForwards() {
        val result = DnsPolicyAdapter(PolicyEngine()).evaluate(query("safe.example.com"))
        assertIs<DnsEvaluation.Forward>(result)
    }

    @Test fun malformedAndCompressedQuestionAreRejected() {
        val adapter = DnsPolicyAdapter(PolicyEngine())
        assertIs<DnsEvaluation.Rejected>(adapter.evaluate(byteArrayOf(1, 2, 3)))
        val compressed = query("example.com").copyOf()
        compressed[12] = 0xc0.toByte()
        assertIs<DnsEvaluation.Rejected>(adapter.evaluate(compressed))
    }

    @Test fun acceptsEdnsOptRecord() {
        val base = query("example.com")
        val packet = base.copyOf(base.size + 11)
        packet[11] = 1
        packet[base.size] = 0
        packet[base.size + 1] = 0
        packet[base.size + 2] = 41
        packet[base.size + 3] = 0x04
        packet[base.size + 4] = 0xd0.toByte() // UDP payload size 1232
        packet[base.size + 5] = 0
        packet[base.size + 6] = 0
        packet[base.size + 7] = 0
        packet[base.size + 8] = 0
        packet[base.size + 9] = 0
        packet[base.size + 10] = 0
        assertIs<DnsEvaluation.Forward>(DnsPolicyAdapter(PolicyEngine()).evaluate(packet))
    }

    @Test fun rejectsTruncatedEdnsOptionTlv() {
        val base = query("example.com")
        val packet = base.copyOf(base.size + 12)
        packet[11] = 1
        packet[base.size] = 0
        packet[base.size + 1] = 0
        packet[base.size + 2] = 41
        packet[base.size + 3] = 0x04
        packet[base.size + 4] = 0xd0.toByte()
        packet[base.size + 9] = 0
        packet[base.size + 10] = 1 // One RDATA byte cannot contain an EDNS option header.
        assertIs<DnsEvaluation.Rejected>(DnsPolicyAdapter(PolicyEngine()).evaluate(packet))
    }

    @Test fun blockedEdnsQueryRetainsOptRecordInResponse() {
        val base = query("ads.example.com")
        val packet = base.copyOf(base.size + 11)
        packet[11] = 1
        packet[base.size] = 0
        packet[base.size + 1] = 0
        packet[base.size + 2] = 41
        packet[base.size + 3] = 0x04
        packet[base.size + 4] = 0xd0.toByte()
        packet[base.size + 7] = 0x80.toByte() // DNSSEC OK
        val result = assertIs<DnsEvaluation.Blocked>(
            DnsPolicyAdapter(PolicyEngine(listOf(rule("ads.example.com", PolicyAction.BLOCK)))).evaluate(packet),
        )
        assertEquals(1, u16(result.response, 10))
        assertEquals(0, u16(result.response, base.size + 9)) // Do not echo client-only EDNS options.
        assertEquals(0x80, result.response[base.size + 7].toInt() and 0xff) // Preserve DO.
        assertEquals(0x04d0, u16(result.response, base.size + 3))
    }

    @Test fun nonInternetDnsClassIsForwardedWithoutDomainPolicy() {
        val packet = query("ads.example.com")
        packet[packet.size - 2] = 0
        packet[packet.size - 1] = 3 // CHAOS class
        val result = assertIs<DnsEvaluation.Forward>(
            DnsPolicyAdapter(PolicyEngine(listOf(rule("ads.example.com", PolicyAction.BLOCK)))).evaluate(packet),
        )
        assertEquals("dns_class_not_filtered", result.decision.reason)
    }

    @Test fun rejectsQueryWithResponseCodeBitsSet() {
        val packet = query("example.com")
        packet[3] = 1
        assertIs<DnsEvaluation.Rejected>(DnsPolicyAdapter(PolicyEngine()).evaluate(packet))
    }

    @Test fun rejectsMultipleQuestionsAndUnsupportedRecords() {
        val packet = query("example.com")
        packet[5] = 2
        assertIs<DnsEvaluation.Rejected>(DnsPolicyAdapter(PolicyEngine()).evaluate(packet))
    }

    private fun rule(domain: String, action: PolicyAction) = PolicyRule(
        id = domain, domain = domain, action = action, source = RuleSource.MANAGED, reason = "test",
    )

    private fun query(domain: String): ByteArray {
        val labels = domain.split('.')
        val name = labels.flatMap { label ->
            listOf(label.length.toByte()) + label.toByteArray(Charsets.US_ASCII).toList()
        } + 0.toByte()
        val question = name.toByteArray() + byteArrayOf(0, 1, 0, 1) // A, IN
        val packet = ByteArray(12 + question.size)
        packet[0] = 0x12
        packet[1] = 0x34
        packet[2] = 0x01 // RD
        packet[5] = 1 // QDCOUNT
        question.copyInto(packet, 12)
        return packet
    }

    private fun u16(bytes: ByteArray, offset: Int) =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)
}
