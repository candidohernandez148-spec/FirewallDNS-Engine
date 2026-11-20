package com.firewalldns.engine.runtime

import com.firewalldns.engine.dns.DnsEvaluation
import com.firewalldns.engine.dns.DnsTcpFrameCodec
import com.firewalldns.engine.dns.DnsTcpFrameDecode
import com.firewalldns.engine.dns.DnsTcpStreamDecoder
import com.firewalldns.engine.dns.DnsUpstreamResult

/**
 * Connection-local DNS-over-TCP framing and policy adapter.
 *
 * Own one instance per accepted smoltcp TCP socket. Feed only bytes returned by
 * that socket's ordered receive stream. The caller remains responsible for TCP
 * sequencing, retransmission, socket limits, polling and lifecycle.
 *
 * Upstream exchanges are synchronous: call [accept] only from a bounded I/O
 * worker, never from the TUN reader or smoltcp packet-poll loop.
 *
 * A malformed DNS message, framing overflow or cancelled upstream exchange
 * terminates this session. OBSERVE is forwarded exactly like ALLOW; BLOCK
 * returns the engine's synthesized response without contacting upstream.
 */
class DnsTcpSessionProcessor(
    private val engine: EngineRuntime,
    private val exchangeUpstream: (ByteArray) -> DnsUpstreamResult,
    maxBufferedBytes: Int = DEFAULT_MAX_BUFFERED_BYTES,
    private val maxFramesPerBatch: Int = DEFAULT_MAX_FRAMES_PER_BATCH,
    private val appPackage: String? = null,
) {
    sealed interface Result {
        data class Batch(
            val framedResponses: List<ByteArray>,
            /** Buffered bytes remain; call accept(emptyArray()) to continue draining. */
            val hasBufferedData: Boolean,
        ) : Result

        data class Closed(val reason: String) : Result
    }

    private val decoder = DnsTcpStreamDecoder(maxBufferedBytes)
    private var closedReason: String? = null

    init {
        require(maxFramesPerBatch in 1..MAX_ALLOWED_FRAMES_PER_BATCH)
    }

    val bufferedBytes: Int
        @Synchronized get() = decoder.bufferedBytes

    val isClosed: Boolean
        @Synchronized get() = closedReason != null

    /**
     * Appends one ordered TCP stream chunk and returns zero or more DNS TCP
     * response frames. A zero-length chunk drains already-buffered coalesced
     * messages after a caller reaches the per-batch work limit.
     */
    @Synchronized
    fun accept(bytes: ByteArray, length: Int = bytes.size): Result {
        closedReason?.let { return Result.Closed(it) }
        if (length < 0 || length > bytes.size) return closeWith("dns_tcp_input_length_invalid")
        if (!decoder.append(bytes, 0, length)) return closeWith("dns_tcp_buffer_limit_exceeded")

        val responses = ArrayList<ByteArray>()
        var processed = 0
        while (processed < maxFramesPerBatch) {
            when (val frame = decoder.pollFrame()) {
                DnsTcpFrameDecode.Incomplete -> return Result.Batch(responses, decoder.hasCompleteFrame)
                is DnsTcpFrameDecode.Invalid -> return closeWith(frame.reason)
                is DnsTcpFrameDecode.Complete -> {
                    val response = evaluate(frame.message) ?: return Result.Closed(closedReason!!)
                    responses += try {
                        DnsTcpFrameCodec.encode(response)
                    } catch (_: IllegalArgumentException) {
                        return closeWith("dns_tcp_response_length_invalid")
                    }
                    processed++
                }
            }
        }
        return Result.Batch(responses, decoder.hasCompleteFrame)
    }

    /** Permanently closes this logical session and clears buffered query bytes. */
    @Synchronized
    fun close(reason: String = "dns_tcp_session_closed") {
        if (closedReason == null) closeWith(reason)
    }

    private fun evaluate(query: ByteArray): ByteArray? {
        return when (val evaluation = engine.evaluateDns(query, appPackage)) {
            is DnsEvaluation.Blocked -> evaluation.response
            is DnsEvaluation.Rejected -> {
                closeWith(evaluation.reason)
                null
            }
            is DnsEvaluation.Forward -> when (val upstream = exchangeUpstream(query)) {
                is DnsUpstreamResult.Success -> upstream.response.message
                is DnsUpstreamResult.Failure -> servfail(evaluation.question)
                DnsUpstreamResult.Cancelled -> {
                    closeWith("dns_tcp_upstream_cancelled")
                    null
                }
            }
        }
    }

    private fun closeWith(reason: String): Result.Closed {
        if (closedReason == null) {
            closedReason = reason.ifBlank { "dns_tcp_session_closed" }
            decoder.reset()
        }
        return Result.Closed(closedReason!!)
    }

    private fun servfail(question: com.firewalldns.engine.dns.DnsQuestion): ByteArray {
        val response = ByteArray(12 + question.wireQuestion.size)
        putU16(response, 0, question.id)
        putU16(
            response,
            2,
            0x8000 or 0x0080 or (question.requestFlags and (0x0100 or 0x0010)) or 0x0002,
        )
        putU16(response, 4, 1)
        question.wireQuestion.copyInto(response, 12)
        return response
    }

    private fun putU16(target: ByteArray, offset: Int, value: Int) {
        target[offset] = (value ushr 8).toByte()
        target[offset + 1] = value.toByte()
    }

    private companion object {
        const val DEFAULT_MAX_BUFFERED_BYTES = 2 * (65_535 + 2)
        const val DEFAULT_MAX_FRAMES_PER_BATCH = 16
        const val MAX_ALLOWED_FRAMES_PER_BATCH = 64
    }
}
