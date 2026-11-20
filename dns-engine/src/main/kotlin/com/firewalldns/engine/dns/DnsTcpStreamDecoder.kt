package com.firewalldns.engine.dns

/**
 * Bounded incremental accumulator for DNS-over-TCP messages.
 *
 * Feed bytes read from one TCP connection, then repeatedly call [pollFrame]
 * until [DnsTcpFrameDecode.Incomplete] is returned. The caller owns TCP
 * sequencing/retransmission and must keep one decoder per connection.
 *
 * The backing storage is allocated once and never grows. An append that would
 * exceed the configured budget is rejected atomically; no buffered bytes are
 * overwritten or discarded.
 */
class DnsTcpStreamDecoder(
    private val maxBufferedBytes: Int = DEFAULT_MAX_BUFFERED_BYTES,
) {
    private val buffer: ByteArray
    private var buffered = 0
    private var failed = false

    init {
        require(maxBufferedBytes >= MIN_FRAME_BYTES) {
            "DNS TCP buffer must fit the two-byte prefix and DNS header"
        }
        require(maxBufferedBytes <= MAX_ALLOWED_BUFFERED_BYTES) {
            "DNS TCP buffer exceeds the configured hard limit"
        }
        buffer = ByteArray(maxBufferedBytes)
    }

    val bufferedBytes: Int
        @Synchronized get() = buffered

    val isFailed: Boolean
        @Synchronized get() = failed

    /**
     * Appends a TCP stream fragment. Returns false on invalid ranges, terminal
     * framing failure, or capacity exhaustion; failure never mutates buffered data.
     */
    @Synchronized
    fun append(source: ByteArray, offset: Int = 0, length: Int = source.size - offset): Boolean {
        if (failed || offset < 0 || length < 0 || offset > source.size - length) return false
        if (length > buffer.size - buffered) return false
        if (length > 0) {
            source.copyInto(buffer, destinationOffset = buffered, startIndex = offset, endIndex = offset + length)
            buffered += length
        }
        return true
    }

    /**
     * Extracts one complete DNS message. Call repeatedly to drain coalesced
     * messages. Invalid framing makes this decoder terminal until [reset].
     */
    @Synchronized
    fun pollFrame(): DnsTcpFrameDecode {
        if (failed) return DnsTcpFrameDecode.Invalid("dns_tcp_stream_failed")
        if (buffered < PREFIX_BYTES) return DnsTcpFrameDecode.Incomplete

        val messageLength = ((buffer[0].toInt() and 0xff) shl 8) or
            (buffer[1].toInt() and 0xff)
        if (messageLength < DNS_HEADER_BYTES) {
            fail()
            return DnsTcpFrameDecode.Invalid("dns_tcp_frame_too_short")
        }

        val frameLength = PREFIX_BYTES + messageLength
        if (buffered < frameLength) return DnsTcpFrameDecode.Incomplete

        val message = buffer.copyOfRange(PREFIX_BYTES, frameLength)
        val remaining = buffered - frameLength
        if (remaining > 0) {
            buffer.copyInto(
                destination = buffer,
                destinationOffset = 0,
                startIndex = frameLength,
                endIndex = buffered,
            )
        }
        buffer.fill(0, remaining, buffered)
        buffered = remaining
        return DnsTcpFrameDecode.Complete(message, frameLength)
    }

    /** Drops connection-local buffered bytes and permits reuse for a new flow. */
    @Synchronized
    fun reset() {
        buffer.fill(0, 0, buffered)
        buffered = 0
        failed = false
    }

    private fun fail() {
        buffer.fill(0, 0, buffered)
        buffered = 0
        failed = true
    }

    private companion object {
        const val PREFIX_BYTES = 2
        const val DNS_HEADER_BYTES = 12
        const val MIN_FRAME_BYTES = PREFIX_BYTES + DNS_HEADER_BYTES
        const val DEFAULT_MAX_BUFFERED_BYTES = 2 * (65_535 + PREFIX_BYTES)
        const val MAX_ALLOWED_BUFFERED_BYTES = 1_048_576
    }
}
