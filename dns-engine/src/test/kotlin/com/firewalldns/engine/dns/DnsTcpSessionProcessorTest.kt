package com.firewalldns.engine.dns

import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.PolicyEngine
import com.firewalldns.engine.core.PolicyRule
import com.firewalldns.engine.core.RuleSource
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicInteger

class DnsTcpSessionProcessorTest {

    @Test
    fun blocksExplicitRuleWithoutUpstreamAndForwardsAllowedWithServfailFallback() {
        val policyEngine = PolicyEngine(
            listOf(
                PolicyRule(
                    id = "block-ads",
                    domain = "ads.example.com",
                    action = PolicyAction.BLOCK,
                    source = RuleSource.USER,
                    reason = "test_user_block",
                ),
            ),
        )
        val adapter = DnsPolicyAdapter(policyEngine)
        val upstreamCalls = AtomicInteger(0)
        var failNextUpstream = false

        val processor = DnsTcpSessionProcessor(
            policyAdapter = adapter,
            exchangeUpstream = { query, _ ->
                upstreamCalls.incrementAndGet()
                if (failNextUpstream) {
                    DnsUpstreamResult.Failure("dns_upstream_tcp_timeout")
                } else {
                    DnsUpstreamResult.Success(
                        DnsUpstreamResponse(positiveResponse(query), DnsUpstreamTransport.TCP),
                    )
                }
            },
        )

        val blockedQuery = dnsQuery("ads.example.com", id = 101)
        val allowedQuery = dnsQuery("api.example.com", id = 102)
        val failQuery = dnsQuery("timeout.example.com", id = 103)

        val r1 = processor.onIncomingBytes(DnsTcpFrameCodec.encode(blockedQuery))
        assertTrue(r1 is DnsTcpSessionProcessor.ProcessResult.Processed)
        assertEquals(0, upstreamCalls.get())

        val r2 = processor.onIncomingBytes(DnsTcpFrameCodec.encode(allowedQuery))
        assertTrue(r2 is DnsTcpSessionProcessor.ProcessResult.Processed)
        assertEquals(1, upstreamCalls.get())

        failNextUpstream = true
        val r3 = processor.onIncomingBytes(DnsTcpFrameCodec.encode(failQuery))
        assertTrue(r3 is DnsTcpSessionProcessor.ProcessResult.Processed)
        assertEquals(2, upstreamCalls.get())

        val outBytes = processor.pollOutbound(65_535)
        val frames = decodeAllFrames(outBytes)
        assertEquals(3, frames.size)
        // NXDOMAIN (RCODE 3)
        assertEquals(101, u16(frames[0], 0))
        assertEquals(3, frames[0][3].toInt() and 0x0f)
        // NOERROR (RCODE 0)
        assertEquals(102, u16(frames[1], 0))
        assertEquals(0, frames[1][3].toInt() and 0x0f)
        // SERVFAIL (RCODE 2)
        assertEquals(103, u16(frames[2], 0))
        assertEquals(2, frames[2][3].toInt() and 0x0f)

        val stats = processor.stats()
        assertEquals(1L, stats.blockedCount)
        assertEquals(1L, stats.forwardedCount)
        assertEquals(1L, stats.servfailCount)
        assertEquals(0, processor.pendingOutboundBytes())
    }

    @Test
    fun respectsBatchLimitAndClosesOnMalformedDnsFrame() {
        val adapter = DnsPolicyAdapter(PolicyEngine(emptyList()))
        val processor = DnsTcpSessionProcessor(
            policyAdapter = adapter,
            exchangeUpstream = { query, _ ->
                DnsUpstreamResult.Success(DnsUpstreamResponse(positiveResponse(query), DnsUpstreamTransport.TCP))
            },
            maxFramesPerBatch = 2,
        )

        val batch = DnsTcpFrameCodec.encode(dnsQuery("a.example", 1)) +
            DnsTcpFrameCodec.encode(dnsQuery("b.example", 2)) +
            DnsTcpFrameCodec.encode(dnsQuery("c.example", 3))

        val first = processor.onIncomingBytes(batch) as DnsTcpSessionProcessor.ProcessResult.Processed
        assertEquals(2, first.framesHandled)
        assertTrue(first.hasMoreWork)
        assertTrue(processor.hasPendingFrames())

        val second = processor.processPendingFrames() as DnsTcpSessionProcessor.ProcessResult.Processed
        assertEquals(1, second.framesHandled)
        assertEquals(false, second.hasMoreWork)

        // Malformed DNS query (qdCount = 0) -> Rejected -> TERMINAL_ERROR
        val malformedDns = ByteArray(12).apply {
            this[0] = 0x01
            this[1] = 0x02
        }
        val err = processor.onIncomingBytes(DnsTcpFrameCodec.encode(malformedDns))
        assertTrue(err is DnsTcpSessionProcessor.ProcessResult.TerminalError)
        assertEquals(DnsTcpSessionProcessor.SessionState.TERMINAL_ERROR, processor.state)
    }

    private fun decodeAllFrames(bytes: ByteArray): List<ByteArray> {
        val dec = DnsTcpStreamDecoder()
        dec.feed(bytes)
        val result = ArrayList<ByteArray>()
        while (true) {
            when (val d = dec.drainFrame()) {
                is DnsTcpStreamDecoder.DrainResult.Frame -> result += d.message
                else -> return result
            }
        }
    }

    private fun dnsQuery(domain: String, id: Int): ByteArray {
        val labels = domain.split('.').flatMap { label ->
            listOf(label.length.toByte()) + label.toByteArray().toList()
        } + 0.toByte()
        val question = labels.toByteArray() + byteArrayOf(0, 1, 0, 1)
        return ByteArray(12 + question.size).also {
            it[0] = (id ushr 8).toByte()
            it[1] = id.toByte()
            it[2] = 1
            it[5] = 1
            question.copyInto(it, 12)
        }
    }

    private fun positiveResponse(query: ByteArray): ByteArray {
        val response = ByteArray(query.size + 16)
        query.copyInto(response)
        response[2] = 0x81.toByte()
        response[3] = 0x80.toByte()
        response[7] = 1
        val offset = query.size
        response[offset] = 0xc0.toByte()
        response[offset + 1] = 0x0c
        response[offset + 3] = 1
        response[offset + 5] = 1
        response[offset + 9] = 60
        response[offset + 11] = 4
        response[offset + 12] = 192.toByte()
        response[offset + 13] = 0
        response[offset + 14] = 2
        response[offset + 15] = 1
        return response
    }

    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)
}
