package com.firewalldns.engine.dns

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs

class DnsTcpFrameCodecTest {
    @Test fun roundTripsDnsMessage() {
        val message = ByteArray(24) { it.toByte() }
        val frame = DnsTcpFrameCodec.encode(message)
        val decoded = assertIs<DnsTcpFrameDecode.Complete>(DnsTcpFrameCodec.decode(frame))
        assertContentEquals(message, decoded.message)
        assertEquals(frame.size, decoded.consumedBytes)
    }

    @Test fun reportsIncompletePrefixAndPayloadWithoutLosingData() {
        assertIs<DnsTcpFrameDecode.Incomplete>(DnsTcpFrameCodec.decode(byteArrayOf(0)))
        assertIs<DnsTcpFrameDecode.Incomplete>(DnsTcpFrameCodec.decode(byteArrayOf(0, 12, 1, 2)))
    }

    @Test fun rejectsFramesShorterThanDnsHeader() {
        assertIs<DnsTcpFrameDecode.Invalid>(DnsTcpFrameCodec.decode(byteArrayOf(0, 11)))
    }

    @Test fun leavesFollowingFramesForCaller() {
        val first = DnsTcpFrameCodec.encode(ByteArray(12) { 1 })
        val second = DnsTcpFrameCodec.encode(ByteArray(16) { 2 })
        val combined = first + second
        val decoded = assertIs<DnsTcpFrameDecode.Complete>(DnsTcpFrameCodec.decode(combined))
        assertEquals(first.size, decoded.consumedBytes)
        assertContentEquals(first.copyOfRange(2, first.size), decoded.message)
    }

    @Test fun refusesInvalidMessageLengthsOnEncode() {
        assertFailsWith<IllegalArgumentException> { DnsTcpFrameCodec.encode(ByteArray(11)) }
    }
}
