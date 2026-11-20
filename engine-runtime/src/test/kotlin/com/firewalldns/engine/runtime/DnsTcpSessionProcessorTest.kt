package com.firewalldns.engine.runtime

import com.firewalldns.engine.core.PolicyAction
import com.firewalldns.engine.core.PolicyRule
import com.firewalldns.engine.core.RuleSource
import com.firewalldns.engine.dns.DnsTcpFrameCodec
import com.firewalldns.engine.dns.DnsUpstreamResponse
import com.firewalldns.engine.dns.DnsUpstreamResult
import com.firewalldns.engine.dns.DnsUpstreamTransport
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class DnsTcpSessionProcessorTest {
    @Test
    fun processesSplitLengthPrefixAndBodyThroughPolicyAndUpstream() {
        val query = query("allowed.example")
        val expectedResponse = response(query)
        var upstreamCalls = 0
        val processor = DnsTcpSessionProcessor(
            engine = EngineRuntime(),
            exchangeUpstream = {
                upstreamCalls++
                DnsUpstreamResult.Success(DnsUpstreamResponse(expectedResponse, DnsUpstreamTransport.UDP))
            },
        )
        val frame = DnsTcpFrameCodec.encode(query)

        assertIs<DnsTcpSessionProcessor.Result.Batch>(processor.accept(frame, 1))
        val partial = assertIs<DnsTcpSessionProcessor.Result.Batch>(processor.accept(frame.copyOfRange(1, 4)))
        assertTrue(partial.framedResponses.isEmpty())
        val completed = assertIs<DnsTcpSessionProcessor.Result.Batch>(
            processor.accept(frame.copyOfRange(4, frame.size)),
        )

        assertEquals(1, upstreamCalls)
        assertEquals(1, completed.framedResponses.size)
        assertContentEquals(DnsTcpFrameCodec.encode(expectedResponse), completed.framedResponses.single())
        assertFalse(processor.isClosed)
    }

    @Test
    fun blockedQuestionReturnsPolicyResponseWithoutUpstream() {
        val query = query("blocked.example")
        val processor = DnsTcpSessionProcessor(
            engine = EngineRuntime(
                initialRules = listOf(
                    PolicyRule(
                        id = "block-test-domain",
                        domain = "blocked.example",
                        action = PolicyAction.BLOCK,
                        source = RuleSource.USER,
                        reason = "test_block",
                    ),
                ),
            ),
            exchangeUpstream = { error("blocked DNS must not reach upstream") },
        )

        val result = assertIs<DnsTcpSessionProcessor.Result.Batch>(
            processor.accept(DnsTcpFrameCodec.encode(query)),
        )
        assertEquals(1, result.framedResponses.size)
        val response = assertIs<com.firewalldns.engine.dns.DnsTcpFrameDecode.Complete>(
            com.firewalldns.engine.dns.DnsTcpFrameCodec.decode(result.framedResponses.single()),
        )
        assertEquals(3, response.message[3].toInt() and 0x0f)
    }

    @Test
    fun coalescedMessagesAreBoundedAndCanBeDrainedInBatches() {
        val queries = listOf(query("one.example"), query("two.example"), query("three.example"))
        val processor = DnsTcpSessionProcessor(
            engine = EngineRuntime(),
            exchangeUpstream = { DnsUpstreamResult.Success(DnsUpstreamResponse(response(it), DnsUpstreamTransport.UDP)) },
            maxFramesPerBatch = 2,
        )

        val first = assertIs<DnsTcpSessionProcessor.Result.Batch>(
            processor.accept(queries.map(DnsTcpFrameCodec::encode).reduce { accumulated, next -> accumulated + next }),
        )
        assertEquals(2, first.framedResponses.size)
        assertTrue(first.hasBufferedData)

        val second = assertIs<DnsTcpSessionProcessor.Result.Batch>(processor.accept(byteArrayOf()))
        assertEquals(1, second.framedResponses.size)
        assertFalse(second.hasBufferedData)
    }

    @Test
    fun malformedDnsClosesSessionAndClearsBufferedBytes() {
        val processor = DnsTcpSessionProcessor(EngineRuntime(), { error("invalid DNS must not reach upstream") })
        val invalidDns = ByteArray(12)
        val result = assertIs<DnsTcpSessionProcessor.Result.Closed>(
            processor.accept(DnsTcpFrameCodec.encode(invalidDns)),
        )
        assertEquals("dns_question_count_unsupported", result.reason)
        assertTrue(processor.isClosed)
        assertEquals(0, processor.bufferedBytes)
        assertEquals(result, processor.accept(byteArrayOf()))
    }

    @Test
    fun bufferOverflowClosesSessionWithoutForwarding() {
        var upstreamCalls = 0
        val processor = DnsTcpSessionProcessor(
            engine = EngineRuntime(),
            exchangeUpstream = {
                upstreamCalls++
                DnsUpstreamResult.Failure("unused")
            },
            maxBufferedBytes = 32,
        )

        val result = assertIs<DnsTcpSessionProcessor.Result.Closed>(
            processor.accept(ByteArray(33)),
        )
        assertEquals("dns_tcp_buffer_limit_exceeded", result.reason)
        assertEquals(0, upstreamCalls)
    }

    @Test
    fun upstreamFailureProducesServfailFrame() {
        val query = query("resolver.example")
        val processor = DnsTcpSessionProcessor(
            engine = EngineRuntime(),
            exchangeUpstream = { DnsUpstreamResult.Failure("dns_upstream_udp_timeout") },
        )

        val result = assertIs<DnsTcpSessionProcessor.Result.Batch>(
            processor.accept(DnsTcpFrameCodec.encode(query)),
        )
        val decoded = assertIs<com.firewalldns.engine.dns.DnsTcpFrameDecode.Complete>(
            com.firewalldns.engine.dns.DnsTcpFrameCodec.decode(result.framedResponses.single()),
        )
        assertEquals(2, decoded.message[3].toInt() and 0x0f)
    }

    private fun query(domain: String): ByteArray {
        val name = domain.split('.').flatMap { label ->
            listOf(label.length.toByte()) + label.toByteArray(Charsets.US_ASCII).toList()
        } + 0.toByte()
        val question = name.toByteArray() + byteArrayOf(0, 1, 0, 1)
        return ByteArray(12 + question.size).also {
            it[0] = 0x12
            it[1] = 0x34
            it[2] = 0x01
            it[5] = 1
            question.copyInto(it, 12)
        }
    }

    private fun response(query: ByteArray): ByteArray =
        query.copyOf().also {
            it[2] = 0x81.toByte()
            it[3] = 0x80.toByte()
        }

}
