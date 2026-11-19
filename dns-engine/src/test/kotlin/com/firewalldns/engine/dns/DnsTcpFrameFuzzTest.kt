package com.firewalldns.engine.dns

import java.util.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs

class DnsTcpFrameFuzzTest {
    @Test
    fun rejectsZeroAndSubHeaderFrameLengths() {
        for (length in 0..11) {
            val frame = byteArrayOf(0, length.toByte())
            assertEquals(
                "dns_tcp_frame_too_short",
                assertIs<DnsTcpFrameDecode.Invalid>(DnsTcpFrameCodec.decode(frame)).reason,
            )
        }
    }

    @Test
    fun preservesInputAndReportsExactConsumptionAtMaximumLength() {
        val message = ByteArray(65_535) { (it and 0xff).toByte() }
        val frame = DnsTcpFrameCodec.encode(message)
        val original = frame.copyOf()
        val decoded = assertIs<DnsTcpFrameDecode.Complete>(DnsTcpFrameCodec.decode(frame))
        assertContentEquals(message, decoded.message)
        assertContentEquals(original, frame)
        assertEquals(65_537, decoded.consumedBytes)
    }

    @Test
    fun deterministicRandomFramesNeverCrashDecoder() {
        val random = Random(0x544350444e53L)
        repeat(15_000) {
            val size = when (it % 6) {
                0 -> 0
                1 -> 1
                2 -> 2
                3 -> 65_537
                else -> random.nextInt(2_049)
            }
            val bytes = ByteArray(size).also(random::nextBytes)
            val decoded = DnsTcpFrameCodec.decode(bytes)
            kotlin.test.assertTrue(
                decoded is DnsTcpFrameDecode.Incomplete ||
                    decoded is DnsTcpFrameDecode.Invalid ||
                    decoded is DnsTcpFrameDecode.Complete,
            )
        }
    }

    @Test
    fun mutatedValidFramesRemainBoundedAndDeterministic() {
        val random = Random(0x4652414d45L)
        val seed = DnsTcpFrameCodec.encode(ByteArray(64) { it.toByte() })
        repeat(8_000) {
            val mutated = seed.copyOf()
            repeat(1 + random.nextInt(4)) {
                val index = random.nextInt(mutated.size)
                mutated[index] = random.nextInt(256).toByte()
            }
            val result = DnsTcpFrameCodec.decode(mutated)
            if (result is DnsTcpFrameDecode.Complete) {
                kotlin.test.assertEquals(
                    2 + result.message.size,
                    result.consumedBytes,
                )
                kotlin.test.assertEquals(true, result.message.size >= 12)
            }
        }
    }
}
