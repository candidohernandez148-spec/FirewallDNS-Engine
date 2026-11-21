package com.firewalldns.engine.dns

import java.io.ByteArrayOutputStream

/**
 * Per-connection DNS-over-TCP processor connecting an incremental stream decoder
 * with policy evaluation (BLOCK / OBSERVE / ALLOW) and upstream exchange.
 */
class DnsTcpSessionProcessor(
    private val evaluateDns: (query: ByteArray, appPackage: String?) -> DnsEvaluation,
    private val exchangeUpstream: (query: ByteArray, cancellation: DnsExchangeCancellation) -> DnsUpstreamResult,
    decoderBufferCapacity: Int = DEFAULT_DECODER_BUFFER_BYTES,
    val maxFramesPerBatch: Int = DEFAULT_MAX_FRAMES_PER_BATCH,
    val maxPendingOutboundBytes: Int = DEFAULT_MAX_PENDING_OUTBOUND_BYTES,
) {
    constructor(
        policyAdapter: DnsPolicyAdapter,
        exchangeUpstream: (query: ByteArray, cancellation: DnsExchangeCancellation) -> DnsUpstreamResult,
        decoderBufferCapacity: Int = DEFAULT_DECODER_BUFFER_BYTES,
        maxFramesPerBatch: Int = DEFAULT_MAX_FRAMES_PER_BATCH,
        maxPendingOutboundBytes: Int = DEFAULT_MAX_PENDING_OUTBOUND_BYTES,
    ) : this(
        evaluateDns = { query, appPackage -> policyAdapter.evaluate(query, appPackage) },
        exchangeUpstream = exchangeUpstream,
        decoderBufferCapacity = decoderBufferCapacity,
        maxFramesPerBatch = maxFramesPerBatch,
        maxPendingOutboundBytes = maxPendingOutboundBytes,
    )

    init {
        require(maxFramesPerBatch > 0) { "maxFramesPerBatch must be positive" }
        require(maxPendingOutboundBytes >= 64) { "maxPendingOutboundBytes must be at least 64" }
    }

    enum class SessionState {
        ACTIVE,
        CLOSED,
        TERMINAL_ERROR,
    }

    sealed interface ProcessResult {
        data class Processed(val framesHandled: Int, val hasMoreWork: Boolean) : ProcessResult
        data object Backpressure : ProcessResult
        data object Closed : ProcessResult
        data class TerminalError(val reason: String) : ProcessResult
    }

    data class SessionStats(
        val state: SessionState,
        val terminalReason: String?,
        val framesDecoded: Long,
        val responsesQueued: Long,
        val blockedCount: Long,
        val forwardedCount: Long,
        val servfailCount: Long,
        val rejectedCount: Long,
        val outboundOverflowCount: Long,
        val pendingOutboundBytes: Int,
        val availableRxWindow: Int,
    )

    private val decoder = DnsTcpStreamDecoder(bufferCapacity = decoderBufferCapacity)
    private val cancellation = DnsExchangeCancellation()
    private val outboundQueue = ArrayDeque<ByteArray>()
    private var outboundHeadOffset: Int = 0
    private var outboundTotalBytes: Int = 0

    @Volatile
    var state: SessionState = SessionState.ACTIVE
        private set

    @Volatile
    var terminalReason: String? = null
        private set

    private var framesDecoded: Long = 0
    private var responsesQueued: Long = 0
    private var blockedCount: Long = 0
    private var forwardedCount: Long = 0
    private var servfailCount: Long = 0
    private var rejectedCount: Long = 0
    private var outboundOverflowCount: Long = 0

    fun availableRxWindow(): Int =
        if (state != SessionState.ACTIVE) 0 else decoder.remainingCapacity()

    fun pendingOutboundBytes(): Int = outboundTotalBytes

    fun hasPendingFrames(): Boolean =
        state == SessionState.ACTIVE && decoder.hasCompleteFrame()

    fun onIncomingBytes(
        chunk: ByteArray,
        offset: Int = 0,
        length: Int = chunk.size,
        appPackage: String? = null,
    ): ProcessResult {
        if (state == SessionState.CLOSED) return ProcessResult.Closed
        if (state == SessionState.TERMINAL_ERROR) {
            return ProcessResult.TerminalError(terminalReason ?: "dns_tcp_session_error")
        }

        when (val feed = decoder.feed(chunk, offset, length)) {
            is DnsTcpStreamDecoder.FeedResult.Accepted -> Unit
            DnsTcpStreamDecoder.FeedResult.BufferFull -> return ProcessResult.Backpressure
            is DnsTcpStreamDecoder.FeedResult.Failed -> return failSession(feed.reason)
        }
        return processPendingFrames(appPackage)
    }

    fun processPendingFrames(appPackage: String? = null): ProcessResult {
        if (state == SessionState.CLOSED) return ProcessResult.Closed
        if (state == SessionState.TERMINAL_ERROR) {
            return ProcessResult.TerminalError(terminalReason ?: "dns_tcp_session_error")
        }

        var handled = 0
        while (handled < maxFramesPerBatch && state == SessionState.ACTIVE) {
            if (outboundTotalBytes >= maxPendingOutboundBytes) {
                return ProcessResult.Processed(handled, decoder.hasCompleteFrame())
            }
            when (val drained = decoder.drainFrame()) {
                DnsTcpStreamDecoder.DrainResult.NeedMoreData -> {
                    return ProcessResult.Processed(handled, hasMoreWork = false)
                }
                is DnsTcpStreamDecoder.DrainResult.Failed -> {
                    return failSession(drained.reason)
                }
                is DnsTcpStreamDecoder.DrainResult.Frame -> {
                    framesDecoded++
                    handled++
                    val evaluation = evaluateDns(drained.message, appPackage)
                    val responseMessage = when (evaluation) {
                        is DnsEvaluation.Blocked -> {
                            blockedCount++
                            evaluation.response
                        }
                        is DnsEvaluation.Forward -> when (val upstream = exchangeUpstream(drained.message, cancellation)) {
                            is DnsUpstreamResult.Success -> {
                                forwardedCount++
                                upstream.response.message
                            }
                            is DnsUpstreamResult.Failure -> {
                                servfailCount++
                                buildServfail(evaluation.question)
                            }
                            DnsUpstreamResult.Cancelled -> {
                                close()
                                return ProcessResult.Closed
                            }
                        }
                        is DnsEvaluation.Rejected -> {
                            rejectedCount++
                            return failSession(evaluation.reason)
                        }
                    }

                    val framed = DnsTcpFrameCodec.encode(responseMessage)
                    if (outboundTotalBytes + framed.size > maxPendingOutboundBytes) {
                        outboundOverflowCount++
                        return failSession("dns_tcp_outbound_buffer_exceeded")
                    }
                    outboundQueue.addLast(framed)
                    outboundTotalBytes += framed.size
                    responsesQueued++
                }
            }
        }
        return ProcessResult.Processed(handled, hasMoreWork = decoder.hasCompleteFrame())
    }

    fun pollOutbound(maxBytes: Int): ByteArray {
        if (maxBytes <= 0 || outboundTotalBytes == 0) return ByteArray(0)
        val targetBytes = minOf(maxBytes, outboundTotalBytes)
        val out = ByteArrayOutputStream(targetBytes)
        var remaining = targetBytes
        while (remaining > 0 && outboundQueue.isNotEmpty()) {
            val head = outboundQueue.first()
            val available = head.size - outboundHeadOffset
            val take = minOf(remaining, available)
            out.write(head, outboundHeadOffset, take)
            outboundHeadOffset += take
            outboundTotalBytes -= take
            remaining -= take
            if (outboundHeadOffset >= head.size) {
                outboundQueue.removeFirst()
                outboundHeadOffset = 0
            }
        }
        return out.toByteArray()
    }

    /** Thread-safe cancellation of any in-flight upstream exchange without waiting on session locks. */
    fun cancelActiveExchange() {
        cancellation.cancel()
    }

    fun close() {
        if (state == SessionState.CLOSED) return
        state = SessionState.CLOSED
        cancellation.cancel()
        decoder.reset()
        outboundQueue.clear()
        outboundHeadOffset = 0
        outboundTotalBytes = 0
    }

    fun stats(): SessionStats = SessionStats(
        state = state,
        terminalReason = terminalReason,
        framesDecoded = framesDecoded,
        responsesQueued = responsesQueued,
        blockedCount = blockedCount,
        forwardedCount = forwardedCount,
        servfailCount = servfailCount,
        rejectedCount = rejectedCount,
        outboundOverflowCount = outboundOverflowCount,
        pendingOutboundBytes = outboundTotalBytes,
        availableRxWindow = availableRxWindow(),
    )

    private fun failSession(reason: String): ProcessResult.TerminalError {
        state = SessionState.TERMINAL_ERROR
        terminalReason = reason
        cancellation.cancel()
        decoder.reset()
        outboundQueue.clear()
        outboundHeadOffset = 0
        outboundTotalBytes = 0
        return ProcessResult.TerminalError(reason)
    }

    private fun buildServfail(question: DnsQuestion): ByteArray {
        val response = ByteArray(12 + question.wireQuestion.size)
        response[0] = (question.id ushr 8).toByte()
        response[1] = question.id.toByte()
        val flags = 0x8000 or 0x0080 or (question.requestFlags and 0x0110) or 0x0002
        response[2] = (flags ushr 8).toByte()
        response[3] = flags.toByte()
        response[4] = 0
        response[5] = 1
        question.wireQuestion.copyInto(response, destinationOffset = 12)
        return response
    }

    companion object {
        const val DEFAULT_DECODER_BUFFER_BYTES = 16_384
        const val DEFAULT_MAX_FRAMES_PER_BATCH = 8
        const val DEFAULT_MAX_PENDING_OUTBOUND_BYTES = 131_072
    }
}
