package com.firewalldns.engine.dns

import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.PolicyEngine
import com.firewalldns.engine.core.PolicyRule
import com.firewalldns.engine.core.RuleSource
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
        assertEquals(0x8003, u16(result.response, 2))
        assertEquals(1, u16(result.response, 4))
        assertContentEquals(request.copyOfRange(12, request.size), result.response.copyOfRange(12, result.response.size))
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

    @Test fun blockedEdnsQueryRetainsOptRecordInResponse() {
        val base = query("ads.example.com")
        val packet = base.copyOf(base.size + 11)
        packet[11] = 1
        packet[base.size] = 0
        packet[base.size + 1] = 0
        packet[base.size + 2] = 41
        packet[base.size + 3] = 0x04
        packet[base.size + 4] = 0xd0.toByte()
        val result = assertIs<DnsEvaluation.Blocked>(
            DnsPolicyAdapter(PolicyEngine(listOf(rule("ads.example.com", PolicyAction.BLOCK)))).evaluate(packet),
        )
        assertEquals(1, u16(result.response, 10))
        assertContentEquals(packet.copyOfRange(base.size, packet.size), result.response.copyOfRange(base.size, result.response.size))
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
