package com.firewalldns.engine.dns

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class DnsTcpStreamDecoderTest {

    @Test
    fun decodesSplitPrefixSplitBodyAndConcatenatedFrames() {
        val decoder = DnsTcpStreamDecoder(bufferCapacity = 256)
        val q1 = dummyDnsQuery("one.example", id = 0x1122)
        val q2 = dummyDnsQuery("two.example", id = 0x3344)
        val framed1 = DnsTcpFrameCodec.encode(q1)
        val framed2 = DnsTcpFrameCodec.encode(q2)

        // Split 2-byte length prefix one byte at a time
        assertTrue(decoder.feed(byteArrayOf(framed1[0])) is DnsTcpStreamDecoder.FeedResult.Accepted)
        assertTrue(decoder.drainFrame() is DnsTcpStreamDecoder.DrainResult.NeedMoreData)

        assertTrue(decoder.feed(byteArrayOf(framed1[1])) is DnsTcpStreamDecoder.FeedResult.Accepted)
        assertTrue(decoder.drainFrame() is DnsTcpStreamDecoder.DrainResult.NeedMoreData)

        // Partial body + rest of frame1 concatenated with frame2
        val splitPoint = 2 + 8
        assertTrue(decoder.feed(framed1, offset = 2, length = 8) is DnsTcpStreamDecoder.FeedResult.Accepted)
        assertTrue(decoder.drainFrame() is DnsTcpStreamDecoder.DrainResult.NeedMoreData)

        val tailAndSecond = framed1.copyOfRange(splitPoint, framed1.size) + framed2
        assertTrue(decoder.feed(tailAndSecond) is DnsTcpStreamDecoder.FeedResult.Accepted)

        val out1 = decoder.drainFrame() as DnsTcpStreamDecoder.DrainResult.Frame
        val out2 = decoder.drainFrame() as DnsTcpStreamDecoder.DrainResult.Frame
        assertArrayEquals(q1, out1.message)
        assertArrayEquals(q2, out2.message)
        assertTrue(decoder.drainFrame() is DnsTcpStreamDecoder.DrainResult.NeedMoreData)
        assertEquals(0, decoder.bufferedBytes)
    }

    @Test
    fun rejectsBufferOverflowAtomicallyWithoutCorruptingPendingBytes() {
        val decoder = DnsTcpStreamDecoder(bufferCapacity = 40)
        val q = dummyDnsQuery("ok.example", id = 1)
        val framed = DnsTcpFrameCodec.encode(q)
        val firstHalf = framed.copyOfRange(0, 12)
        assertTrue(decoder.feed(firstHalf) is DnsTcpStreamDecoder.FeedResult.Accepted)
        assertEquals(28, decoder.remainingCapacity())

        // Oversized chunk exceeding remaining capacity must fail atomically
        val oversized = ByteArray(29) { 0x42 }
        assertEquals(DnsTcpStreamDecoder.FeedResult.BufferFull, decoder.feed(oversized))
        assertEquals(12, decoder.bufferedBytes)
        assertFalse(decoder.isFailed)

        // Feeding remaining valid bytes still decodes cleanly
        assertTrue(decoder.feed(framed, 12, framed.size - 12) is DnsTcpStreamDecoder.FeedResult.Accepted)
        val decoded = decoder.drainFrame() as DnsTcpStreamDecoder.DrainResult.Frame
        assertArrayEquals(q, decoded.message)
    }

    @Test
    fun entersTerminalErrorOnInvalidFrameLengthAndClearsOnReset() {
        val decoder = DnsTcpStreamDecoder(bufferCapacity = 128, maxMessageBytes = 64)

        // Frame length 11 (< 12 minimum DNS header)
        val tooShort = decoder.feed(byteArrayOf(0x00, 0x0b, 0x01, 0x02))
        assertTrue(tooShort is DnsTcpStreamDecoder.FeedResult.Failed)
        assertEquals("dns_tcp_frame_too_short", (tooShort as DnsTcpStreamDecoder.FeedResult.Failed).reason)
        assertTrue(decoder.isFailed)
        assertEquals(0, decoder.remainingCapacity())

        decoder.reset()
        assertFalse(decoder.isFailed)
        assertEquals(128, decoder.remainingCapacity())

        // Frame length > maxMessageBytes (65 > 64)
        val tooLarge = decoder.feed(byteArrayOf(0x00, 0x41))
        assertTrue(tooLarge is DnsTcpStreamDecoder.FeedResult.Failed)
        assertEquals("dns_tcp_frame_too_large", (tooLarge as DnsTcpStreamDecoder.FeedResult.Failed).reason)
    }

    private fun dummyDnsQuery(domain: String, id: Int): ByteArray {
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
}
