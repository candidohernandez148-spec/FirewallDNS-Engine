package com.firewalldns.engine.dns

/**
 * Bounded, incremental RFC 1035 Section 4.2.2 DNS-over-TCP stream decoder.
 * One instance belongs to a single TCP connection; there is no dynamic buffer growth.
 */
class DnsTcpStreamDecoder(
    val bufferCapacity: Int = DEFAULT_BUFFER_CAPACITY,
    val maxMessageBytes: Int = MAX_DNS_MESSAGE_BYTES,
) {
    init {
        require(maxMessageBytes in MIN_DNS_MESSAGE_BYTES..MAX_DNS_MESSAGE_BYTES) {
            "maxMessageBytes must be in $MIN_DNS_MESSAGE_BYTES..$MAX_DNS_MESSAGE_BYTES"
        }
        require(bufferCapacity >= 2 + MIN_DNS_MESSAGE_BYTES) {
            "bufferCapacity must hold at least a 2-byte prefix and a 12-byte DNS header"
        }
    }

    sealed interface FeedResult {
        data class Accepted(val bufferedBytes: Int) : FeedResult
        data object BufferFull : FeedResult
        data class Failed(override val reason: String) : FailedResult, FeedResult
    }

    sealed interface DrainResult {
        data class Frame(val message: ByteArray) : DrainResult
        data object NeedMoreData : DrainResult
        data class Failed(override val reason: String) : FailedResult, DrainResult
    }

    sealed interface FailedResult {
        val reason: String
    }

    private val buffer = ByteArray(bufferCapacity)
    private var size: Int = 0
    private var terminalError: String? = null

    val bufferedBytes: Int
        get() = size

    val failureReason: String?
        get() = terminalError

    val isFailed: Boolean
        get() = terminalError != null

    fun remainingCapacity(): Int = if (terminalError != null) 0 else bufferCapacity - size

    fun feed(chunk: ByteArray, offset: Int = 0, length: Int = chunk.size): FeedResult {
        require(offset >= 0 && length >= 0 && offset + length <= chunk.size) {
            "Invalid chunk slice: offset=$offset, length=$length, size=${chunk.size}"
        }
        terminalError?.let { return FeedResult.Failed(it) }
        if (length == 0) return FeedResult.Accepted(size)
        if (length > bufferCapacity - size) return FeedResult.BufferFull

        chunk.copyInto(buffer, destinationOffset = size, startIndex = offset, endIndex = offset + length)
        size += length
        validatePendingHeader()?.let { error ->
            terminalError = error
            return FeedResult.Failed(error)
        }
        return FeedResult.Accepted(size)
    }

    fun drainFrame(): DrainResult {
        terminalError?.let { return DrainResult.Failed(it) }
        if (size < 2) return DrainResult.NeedMoreData

        val frameLength = ((buffer[0].toInt() and 0xff) shl 8) or (buffer[1].toInt() and 0xff)
        validateFrameLength(frameLength)?.let { error ->
            terminalError = error
            return DrainResult.Failed(error)
        }
        val totalFrameBytes = 2 + frameLength
        if (size < totalFrameBytes) return DrainResult.NeedMoreData

        val frame = buffer.copyOfRange(2, totalFrameBytes)
        val remaining = size - totalFrameBytes
        if (remaining > 0) {
            buffer.copyInto(buffer, destinationOffset = 0, startIndex = totalFrameBytes, endIndex = size)
        }
        size = remaining

        validatePendingHeader()?.let { error ->
            terminalError = error
        }
        return DrainResult.Frame(frame)
    }

    fun hasCompleteFrame(): Boolean {
        if (terminalError != null || size < 2) return false
        val frameLength = ((buffer[0].toInt() and 0xff) shl 8) or (buffer[1].toInt() and 0xff)
        return frameLength in MIN_DNS_MESSAGE_BYTES..maxMessageBytes && size >= 2 + frameLength
    }

    fun reset() {
        size = 0
        terminalError = null
        buffer.fill(0)
    }

    private fun validatePendingHeader(): String? {
        if (size < 2) return null
        val frameLength = ((buffer[0].toInt() and 0xff) shl 8) or (buffer[1].toInt() and 0xff)
        return validateFrameLength(frameLength)
    }

    private fun validateFrameLength(frameLength: Int): String? = when {
        frameLength < MIN_DNS_MESSAGE_BYTES -> "dns_tcp_frame_too_short"
        frameLength > maxMessageBytes -> "dns_tcp_frame_too_large"
        else -> null
    }

    companion object {
        const val MIN_DNS_MESSAGE_BYTES = 12
        const val MAX_DNS_MESSAGE_BYTES = 65_535
        const val DEFAULT_BUFFER_CAPACITY = 65_537
    }
}
