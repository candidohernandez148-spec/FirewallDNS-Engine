package com.firewalldns.engine.dns

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

class DnsTcpStreamDecoderTest {
    @Test
    fun accumulatesSplitPrefixAndSplitMessageBody() {
        val message = ByteArray(24) { (it + 1).toByte() }
        val frame = DnsTcpFrameCodec.encode(message)
        val decoder = DnsTcpStreamDecoder()

        assertTrue(decoder.append(frame, 0, 1))
        assertIs<DnsTcpFrameDecode.Incomplete>(decoder.pollFrame())
        assertTrue(decoder.append(frame, 1, 2))
        assertIs<DnsTcpFrameDecode.Incomplete>(decoder.pollFrame())
        assertTrue(decoder.append(frame, 3, frame.size - 3))

        val decoded = assertIs<DnsTcpFrameDecode.Complete>(decoder.pollFrame())
        assertContentEquals(message, decoded.message)
        assertEquals(frame.size, decoded.consumedBytes)
        assertEquals(0, decoder.bufferedBytes)
    }

    @Test
    fun drainsMultipleCoalescedMessagesInOrder() {
        val first = ByteArray(12) { 0x11 }
        val second = ByteArray(32) { 0x22 }
        val third = ByteArray(15) { 0x33 }
        val decoder = DnsTcpStreamDecoder()

        assertTrue(decoder.append(
            DnsTcpFrameCodec.encode(first) + DnsTcpFrameCodec.encode(second) + DnsTcpFrameCodec.encode(third)
        ))
        assertContentEquals(first, assertIs<DnsTcpFrameDecode.Complete>(decoder.pollFrame()).message)
        assertContentEquals(second, assertIs<DnsTcpFrameDecode.Complete>(decoder.pollFrame()).message)
        assertContentEquals(third, assertIs<DnsTcpFrameDecode.Complete>(decoder.pollFrame()).message)
        assertIs<DnsTcpFrameDecode.Incomplete>(decoder.pollFrame())
        assertEquals(0, decoder.bufferedBytes)
    }

    @Test
    fun reportsOnlyFramesThatCanBeConsumedWithoutWaitingForMoreBytes() {
        val frame = DnsTcpFrameCodec.encode(ByteArray(12))
        val decoder = DnsTcpStreamDecoder()

        assertTrue(decoder.append(frame, 0, frame.size - 1))
        assertFalse(decoder.hasCompleteFrame)
        assertTrue(decoder.append(frame, frame.size - 1, 1))
        assertTrue(decoder.hasCompleteFrame)
        assertIs<DnsTcpFrameDecode.Complete>(decoder.pollFrame())
        assertFalse(decoder.hasCompleteFrame)

        assertTrue(decoder.append(byteArrayOf(0, 11)))
        assertTrue(decoder.hasCompleteFrame)
    }

    @Test
    fun rejectsCapacityOverflowAtomically() {
        val decoder = DnsTcpStreamDecoder(maxBufferedBytes = 64)
        val prefixAndPartial = byteArrayOf(0, 40, 1, 2, 3)
        assertTrue(decoder.append(prefixAndPartial))
        val before = decoder.bufferedBytes

        assertFalse(decoder.append(ByteArray(60)))
        assertEquals(before, decoder.bufferedBytes)
        assertIs<DnsTcpFrameDecode.Incomplete>(decoder.pollFrame())
    }

    @Test
    fun invalidLengthPoisonsDecoderUntilReset() {
        val decoder = DnsTcpStreamDecoder()
        assertTrue(decoder.append(byteArrayOf(0, 11)))
        assertIs<DnsTcpFrameDecode.Invalid>(decoder.pollFrame())
        assertTrue(decoder.isFailed)
        assertFalse(decoder.append(DnsTcpFrameCodec.encode(ByteArray(12))))
        assertIs<DnsTcpFrameDecode.Invalid>(decoder.pollFrame())

        decoder.reset()
        assertFalse(decoder.isFailed)
        assertTrue(decoder.append(DnsTcpFrameCodec.encode(ByteArray(12))))
        assertIs<DnsTcpFrameDecode.Complete>(decoder.pollFrame())
    }

    @Test
    fun supportsMaximumDnsTcpMessageLength() {
        val message = ByteArray(65_535) { 0x5a }
        val frame = DnsTcpFrameCodec.encode(message)
        val decoder = DnsTcpStreamDecoder()

        assertTrue(decoder.append(frame))
        val decoded = assertIs<DnsTcpFrameDecode.Complete>(decoder.pollFrame())
        assertContentEquals(message, decoded.message)
    }

    @Test
    fun rejectsInvalidAppendRangesWithoutChangingState() {
        val decoder = DnsTcpStreamDecoder()
        assertFalse(decoder.append(byteArrayOf(1, 2), offset = -1, length = 1))
        assertFalse(decoder.append(byteArrayOf(1, 2), offset = 1, length = 2))
        assertEquals(0, decoder.bufferedBytes)
    }
}
