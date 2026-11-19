package com.firewalldns.engine.dns

sealed interface DnsTcpFrameDecode {
    data object Incomplete : DnsTcpFrameDecode
    data class Invalid(val reason: String) : DnsTcpFrameDecode
    data class Complete(val message: ByteArray, val consumedBytes: Int) : DnsTcpFrameDecode
}

/**
 * Codec for the two-byte length prefix used by DNS over TCP.
 * Stream reads may be partial; callers retain buffered bytes when Incomplete is returned.
 */
object DnsTcpFrameCodec {
    fun decode(buffer: ByteArray): DnsTcpFrameDecode {
        if (buffer.size < PREFIX_SIZE) return DnsTcpFrameDecode.Incomplete
        val length = ((buffer[0].toInt() and 0xff) shl 8) or (buffer[1].toInt() and 0xff)
        if (length < DNS_HEADER_SIZE) return DnsTcpFrameDecode.Invalid("dns_tcp_frame_too_short")
        val totalLength = PREFIX_SIZE + length
        if (buffer.size < totalLength) return DnsTcpFrameDecode.Incomplete
        return DnsTcpFrameDecode.Complete(
            message = buffer.copyOfRange(PREFIX_SIZE, totalLength),
            consumedBytes = totalLength,
        )
    }

    fun encode(message: ByteArray): ByteArray {
        require(message.size in DNS_HEADER_SIZE..MAX_DNS_MESSAGE_SIZE) {
            "DNS TCP message length must be between $DNS_HEADER_SIZE and $MAX_DNS_MESSAGE_SIZE"
        }
        return ByteArray(PREFIX_SIZE + message.size).also { frame ->
            frame[0] = (message.size ushr 8).toByte()
            frame[1] = message.size.toByte()
            message.copyInto(frame, destinationOffset = PREFIX_SIZE)
        }
    }

    private const val PREFIX_SIZE = 2
    private const val DNS_HEADER_SIZE = 12
    private const val MAX_DNS_MESSAGE_SIZE = 65_535
}
