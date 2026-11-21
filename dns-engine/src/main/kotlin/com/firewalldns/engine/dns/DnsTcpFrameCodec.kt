package com.firewalldns.engine.dns

/** RFC 1035 Section 4.2.2 two-byte length-prefixed DNS-over-TCP framing. */
object DnsTcpFrameCodec {
    fun encode(message: ByteArray): ByteArray {
        require(message.size in 1..65_535) { "DNS TCP frame size out of range: ${message.size}" }
        val framed = ByteArray(2 + message.size)
        framed[0] = (message.size ushr 8).toByte()
        framed[1] = message.size.toByte()
        message.copyInto(framed, destinationOffset = 2)
        return framed
    }
}
