package com.firewalldns.engine.dns

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

class DnsUpstreamResponseValidatorTest {
    @Test fun acceptsStructurallyValidResponse() {
        val query = query()
        assertNull(DnsUpstreamResponseValidator.validate(positiveResponse(query), question(query)))
    }

    @Test fun rejectsResourceRecordLengthBeyondPacket() {
        val query = query()
        val response = positiveResponse(query)
        putU16(response, query.size + 10, 32)
        assertEquals(
            "dns_upstream_record_data_truncated",
            DnsUpstreamResponseValidator.validate(response, question(query)),
        )
    }

    @Test fun rejectsForwardOrSelfReferencingCompressionPointer() {
        val query = query()
        val response = positiveResponse(query)
        response[query.size] = 0xc0.toByte()
        response[query.size + 1] = query.size.toByte()
        assertEquals(
            "dns_upstream_record_name_malformed",
            DnsUpstreamResponseValidator.validate(response, question(query)),
        )
    }

    @Test fun rejectsTrailingBytesAfterDeclaredRecords() {
        val query = query()
        val response = positiveResponse(query) + byteArrayOf(0)
        assertEquals(
            "dns_upstream_response_trailing_bytes",
            DnsUpstreamResponseValidator.validate(response, question(query)),
        )
    }

    @Test fun rejectsMalformedEdnsOptionFraming() {
        val query = query()
        val response = query.copyOf(query.size + 12)
        query.copyInto(response)
        response[2] = 0x81.toByte()
        response[3] = 0x80.toByte()
        response[11] = 1
        val offset = query.size
        response[offset] = 0
        putU16(response, offset + 1, 41)
        putU16(response, offset + 3, 1232)
        putU16(response, offset + 9, 1)
        response[offset + 11] = 0 // Truncated option header.
        assertEquals(
            "dns_upstream_edns_option_header_truncated",
            DnsUpstreamResponseValidator.validate(response, question(query)),
        )
    }

    private fun query(): ByteArray {
        val name = byteArrayOf(7, 101, 120, 97, 109, 112, 108, 101, 3, 99, 111, 109, 0)
        val question = name + byteArrayOf(0, 1, 0, 1)
        return ByteArray(12 + question.size).also {
            it[0] = 0x12
            it[1] = 0x34
            it[2] = 1
            it[5] = 1
            question.copyInto(it, 12)
        }
    }

    private fun question(query: ByteArray) = query.copyOfRange(12, query.size)

    private fun positiveResponse(query: ByteArray): ByteArray =
        ByteArray(query.size + 16).also { response ->
            query.copyInto(response)
            response[2] = 0x81.toByte()
            response[3] = 0x80.toByte()
            response[7] = 1
            val offset = query.size
            response[offset] = 0xc0.toByte()
            response[offset + 1] = 0x0c
            putU16(response, offset + 2, 1)
            putU16(response, offset + 4, 1)
            response[offset + 9] = 60
            putU16(response, offset + 10, 4)
            response[offset + 12] = 192.toByte()
            response[offset + 14] = 2
            response[offset + 15] = 1
        }

    private fun putU16(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value ushr 8).toByte()
        bytes[offset + 1] = value.toByte()
    }
}
