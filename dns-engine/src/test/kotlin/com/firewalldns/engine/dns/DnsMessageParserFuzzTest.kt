package com.firewalldns.engine.dns

import java.util.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Deterministic robustness tests for untrusted DNS datagrams.
 *
 * This is a bounded, reproducible smoke-fuzzer, not a replacement for
 * coverage-guided fuzzing on a dedicated CI/nightly runner.
 */
class DnsMessageParserFuzzTest {

    @Test
    fun rejectsKnownMalformedDnsMessages() {
        val valid = query("example.com")
        val cases = listOf(
            ByteArray(0),
            ByteArray(11),
            valid.copyOf().also { it[2] = 0x80.toByte() }, // QR set on a query
            valid.copyOf().also { it[5] = 0 }, // QDCOUNT = 0
            valid.copyOf().also { it[5] = 2 }, // QDCOUNT = 2
            valid.copyOf().also { it[12] = 0xc0.toByte() }, // compressed QNAME
            valid.copyOf().also { it[12] = 64 }, // label > 63 bytes
            valid.copyOf(valid.size - 1), // truncated question
            valid + byteArrayOf(0), // trailing data
            valid.copyOf().also { it[11] = 1 }, // OPT declared but absent
        )

        cases.forEach { packet ->
            assertIs<DnsParseResult.Invalid>(DnsMessageParser.parse(packet))
        }
    }

    @Test
    fun acceptsValidQueryAndDoesNotMutateInput() {
        val packet = query("www.example.com")
        val original = packet.copyOf()

        val parsed = assertIs<DnsParseResult.Valid>(DnsMessageParser.parse(packet))

        assertTrue(parsed.question.domain == "www.example.com")
        assertContentEquals(original, packet)
    }

    @Test
    fun deterministicRandomInputsNeverCrashParser() {
        val random = Random(0x46444e53L)

        repeat(12_000) {
            val size = when (it % 8) {
                0 -> 0
                1 -> 11
                2 -> 12
                3 -> 65_535
                else -> random.nextInt(1_025)
            }
            val packet = ByteArray(size).also(random::nextBytes)
            // The parser must return a typed result for every byte sequence.
            val result = DnsMessageParser.parse(packet)
            assertTrue(result is DnsParseResult.Valid || result is DnsParseResult.Invalid)
        }
    }

    @Test
    fun mutationsOfValidQueriesNeverCrashParser() {
        val random = Random(0x4d55544154454cL)
        val seed = query("api.service.example")
        repeat(8_000) {
            val mutated = seed.copyOf()
            repeat(1 + random.nextInt(4)) {
                val index = random.nextInt(mutated.size)
                mutated[index] = random.nextInt(256).toByte()
            }
            val result = DnsMessageParser.parse(mutated)
            assertTrue(result is DnsParseResult.Valid || result is DnsParseResult.Invalid)
        }
    }

    private fun query(domain: String): ByteArray {
        val labels = domain.split('.')
        val qname = labels.flatMap { label ->
            listOf(label.length.toByte()) + label.toByteArray(Charsets.US_ASCII).toList()
        } + 0.toByte()
        val question = qname.toByteArray() + byteArrayOf(0, 1, 0, 1)
        return ByteArray(12 + question.size).also {
            it[0] = 0x12
            it[1] = 0x34
            it[2] = 0x01
            it[5] = 1
            question.copyInto(it, 12)
        }
    }
}
