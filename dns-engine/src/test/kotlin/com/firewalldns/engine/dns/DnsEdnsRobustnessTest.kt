package com.firewalldns.engine.dns

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

class DnsEdnsRobustnessTest {
    @Test
    fun parsesEdnsOptAndMultipleWellFormedOptions() {
        val packet = queryWithOpt(byteArrayOf(
            0x00, 0x08, 0x00, 0x02, 0x12, 0x34,
            0x00, 0x0a, 0x00, 0x01, 0x7f,
        ), dnssecOk = true)

        val question = assertIs<DnsParseResult.Valid>(DnsMessageParser.parse(packet)).question
        assertEquals("a.example", question.domain)
        assertEquals(1_232, question.ednsUdpPayloadSize)
        assertEquals(true, question.ednsDnssecOk)
    }

    @Test
    fun acceptsEmptyEdnsOptionSection() {
        val question = assertIs<DnsParseResult.Valid>(
            DnsMessageParser.parse(queryWithOpt(byteArrayOf())),
        ).question
        assertEquals(1_232, question.ednsUdpPayloadSize)
        assertEquals(false, question.ednsDnssecOk)
    }

    @Test
    fun rejectsTruncatedEdnsOptionHeader() {
        val packet = queryWithOpt(byteArrayOf(0x00, 0x08, 0x00))
        assertEquals(
            "dns_opt_option_header_truncated",
            assertIs<DnsParseResult.Invalid>(DnsMessageParser.parse(packet)).reason,
        )
    }

    @Test
    fun rejectsEdnsOptionWhoseDataExceedsRdata() {
        val packet = queryWithOpt(byteArrayOf(0x00, 0x08, 0x00, 0x04, 0x01))
        assertEquals(
            "dns_opt_option_data_truncated",
            assertIs<DnsParseResult.Invalid>(DnsMessageParser.parse(packet)).reason,
        )
    }

    @Test
    fun rejectsOptRdataLengthThatDoesNotMatchPacket() {
        val packet = queryWithOpt(byteArrayOf()).also { it[it.size - 1] = 1 }
        assertEquals(
            "dns_opt_rdata_length_invalid",
            assertIs<DnsParseResult.Invalid>(DnsMessageParser.parse(packet)).reason,
        )
    }

    @Test
    fun deterministicEdnsMutationsNeverCrashParser() {
        val random = java.util.Random(0x45444e53544c56L)
        val seed = queryWithOpt(byteArrayOf(0x00, 0x08, 0x00, 0x02, 0x01, 0x02))
        repeat(5_000) {
            val mutated = seed.copyOf()
            repeat(1 + random.nextInt(3)) {
                val index = 12 + random.nextInt(mutated.size - 12)
                mutated[index] = random.nextInt(256).toByte()
            }
            val result = DnsMessageParser.parse(mutated)
            kotlin.test.assertTrue(result is DnsParseResult.Valid || result is DnsParseResult.Invalid)
        }
    }

    private fun queryWithOpt(options: ByteArray, dnssecOk: Boolean = false): ByteArray {
        val qname = byteArrayOf(1, 'a'.code.toByte(), 7) +
            "example".toByteArray(Charsets.US_ASCII) + byteArrayOf(0)
        val question = qname + byteArrayOf(0, 1, 0, 1)
        val opt = byteArrayOf(
            0, 0, 41, 4, 0xd0.toByte(),
            0, 0, if (dnssecOk) 0x80.toByte() else 0, 0,
            (options.size ushr 8).toByte(), options.size.toByte(),
        ) + options
        return ByteArray(12).also {
            it[0] = 0x12
            it[1] = 0x34
            it[2] = 0x01
            it[5] = 1
            it[11] = 1
        } + question + opt
    }
}
