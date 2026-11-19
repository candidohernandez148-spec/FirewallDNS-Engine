package com.firewalldns.engine.dns

import java.nio.charset.StandardCharsets

data class DnsQuestion(
    val id: Int,
    val requestFlags: Int,
    val domain: String,
    val type: Int,
    val dnsClass: Int,
    /** Exact question bytes (QNAME, QTYPE, QCLASS), safe to copy into a reply. */
    val wireQuestion: ByteArray,
    val ednsUdpPayloadSize: Int?,
    val ednsDnssecOk: Boolean,
)

sealed interface DnsParseResult {
    data class Valid(val question: DnsQuestion) : DnsParseResult
    data class Invalid(val reason: String) : DnsParseResult
}

/**
 * Strict parser for a single-question DNS query.
 * Accepts no answer/authority records and at most one EDNS(0) OPT record.
 * Transport framing (UDP datagram or TCP length prefix) belongs to the adapter.
 */
object DnsMessageParser {
    fun parse(packet: ByteArray): DnsParseResult {
        if (packet.size < HEADER_SIZE) return invalid("dns_header_truncated")
        if (packet.size > MAX_MESSAGE_SIZE) return invalid("dns_message_too_large")

        val id = u16(packet, 0)
        val flags = u16(packet, 2)
        val qdCount = u16(packet, 4)
        val anCount = u16(packet, 6)
        val nsCount = u16(packet, 8)
        val arCount = u16(packet, 10)

        if (flags and 0x8000 != 0) return invalid("dns_response_not_query")
        if ((flags ushr 11) and 0x0f != 0) return invalid("dns_opcode_unsupported")
        if (flags and 0x0200 != 0) return invalid("dns_truncated_query")
        if (flags and 0x0040 != 0) return invalid("dns_reserved_flag_set")
        if (qdCount != 1) return invalid("dns_question_count_unsupported")
        if (anCount != 0 || nsCount != 0) return invalid("dns_query_sections_unsupported")
        if (arCount > 1) return invalid("dns_additional_count_unsupported")

        var offset = HEADER_SIZE
        val questionStart = offset
        val labels = ArrayList<String>()
        var wireNameLength = 1
        while (true) {
            if (offset >= packet.size) return invalid("dns_qname_truncated")
            val length = packet[offset++].toInt() and 0xff
            if (length == 0) break
            if (length and 0xc0 != 0) return invalid("dns_qname_compression_unsupported")
            if (length > 63) return invalid("dns_label_too_long")
            if (offset + length > packet.size) return invalid("dns_label_truncated")
            wireNameLength += length + 1
            if (wireNameLength > 255) return invalid("dns_qname_too_long")
            val bytes = packet.copyOfRange(offset, offset + length)
            if (bytes.any { (it.toInt() and 0xff) !in 0x21..0x7e || it == '.'.code.toByte() }) {
                return invalid("dns_label_non_hostname_ascii")
            }
            labels += String(bytes, StandardCharsets.US_ASCII)
            offset += length
        }
        if (labels.isEmpty()) return invalid("dns_root_name_unsupported")
        if (offset + 4 > packet.size) return invalid("dns_question_truncated")
        val type = u16(packet, offset)
        val dnsClass = u16(packet, offset + 2)
        offset += 4
        val questionEnd = offset
        var ednsUdpPayloadSize: Int? = null
        var ednsDnssecOk = false
        if (arCount == 1) {
            if (offset + 11 > packet.size) return invalid("dns_opt_truncated")
            if ((packet[offset++].toInt() and 0xff) != 0) return invalid("dns_opt_owner_unsupported")
            if (u16(packet, offset) != TYPE_OPT) return invalid("dns_additional_record_unsupported")
            offset += 2
            ednsUdpPayloadSize = u16(packet, offset)
            offset += 4
            ednsDnssecOk = u16(packet, offset - 2) and 0x8000 != 0
            val rdLength = u16(packet, offset)
            offset += 2
            if (offset + rdLength != packet.size) return invalid("dns_opt_rdata_length_invalid")
            offset += rdLength
        }
        if (offset != packet.size) return invalid("dns_trailing_bytes")

        return DnsParseResult.Valid(
            DnsQuestion(
                id = id,
                requestFlags = flags,
                domain = labels.joinToString("."),
                type = type,
                dnsClass = dnsClass,
                wireQuestion = packet.copyOfRange(questionStart, questionEnd),
                ednsUdpPayloadSize = ednsUdpPayloadSize,
                ednsDnssecOk = ednsDnssecOk,
            ),
        )
    }

    private fun invalid(reason: String) = DnsParseResult.Invalid(reason)
    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private const val HEADER_SIZE = 12
    private const val MAX_MESSAGE_SIZE = 65_535
    private const val CLASS_IN = 1
    private const val TYPE_OPT = 41
}
