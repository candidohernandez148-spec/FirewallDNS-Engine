package com.firewalldns.engine.dns

internal object DnsUpstreamResponseValidator {
    fun validate(message: ByteArray, expectedQuestion: ByteArray): String? {
        if (message.size < HEADER_SIZE) return "dns_upstream_response_header_truncated"
        if (message.size > MAX_MESSAGE_SIZE) return "dns_upstream_response_too_large"
        if (u16(message, 4) != 1) return "dns_upstream_question_count_unsupported"

        val questionEnd = skipName(message, HEADER_SIZE) ?: return "dns_upstream_question_malformed"
        if (questionEnd + 4 > message.size) return "dns_upstream_response_question_truncated"
        val actualQuestion = message.copyOfRange(HEADER_SIZE, questionEnd + 4)
        if (!actualQuestion.contentEquals(expectedQuestion)) return "dns_upstream_question_mismatch"

        val answerCount = u16(message, 6)
        val authorityCount = u16(message, 8)
        val additionalCount = u16(message, 10)
        val totalRecords = answerCount + authorityCount + additionalCount
        if (totalRecords > MAX_RECORDS) return "dns_upstream_record_count_unsupported"

        var offset = questionEnd + 4
        var optCount = 0
        repeat(totalRecords) { index ->
            val ownerEnd = skipName(message, offset) ?: return "dns_upstream_record_name_malformed"
            if (ownerEnd + RR_FIXED_SIZE > message.size) return "dns_upstream_record_header_truncated"
            val type = u16(message, ownerEnd)
            val dataLength = u16(message, ownerEnd + 8)
            val dataStart = ownerEnd + RR_FIXED_SIZE
            val dataEnd = dataStart + dataLength
            if (dataEnd < dataStart || dataEnd > message.size) return "dns_upstream_record_data_truncated"

            if (type == TYPE_OPT) {
                optCount++
                if (index < answerCount + authorityCount || optCount > 1) {
                    return "dns_upstream_edns_record_position_invalid"
                }
                if (ownerEnd != offset + 1 || (message[offset].toInt() and 0xff) != 0) {
                    return "dns_upstream_edns_owner_invalid"
                }
                var optionOffset = dataStart
                while (optionOffset < dataEnd) {
                    if (optionOffset + 4 > dataEnd) return "dns_upstream_edns_option_header_truncated"
                    val optionLength = u16(message, optionOffset + 2)
                    optionOffset += 4
                    if (optionOffset + optionLength > dataEnd) {
                        return "dns_upstream_edns_option_data_truncated"
                    }
                    optionOffset += optionLength
                }
            }
            offset = dataEnd
        }
        if (offset != message.size) return "dns_upstream_response_trailing_bytes"
        return null
    }

    private fun skipName(message: ByteArray, start: Int): Int? {
        if (start !in message.indices) return null
        var cursor = start
        var jumped = false
        var consumed = -1
        var expandedLength = 0
        var steps = 0
        while (steps++ < MAX_NAME_STEPS) {
            if (cursor !in message.indices) return null
            val length = message[cursor].toInt() and 0xff
            when {
                length == 0 -> {
                    expandedLength++
                    if (expandedLength > MAX_NAME_LENGTH) return null
                    return if (jumped) consumed else cursor + 1
                }
                length and 0xc0 == 0xc0 -> {
                    if (cursor + 1 >= message.size) return null
                    val pointer = ((length and 0x3f) shl 8) or (message[cursor + 1].toInt() and 0xff)
                    if (pointer >= cursor || pointer >= message.size) return null
                    if (!jumped) consumed = cursor + 2
                    jumped = true
                    cursor = pointer
                }
                length and 0xc0 != 0 || length > MAX_LABEL_LENGTH -> return null
                else -> {
                    if (cursor + 1 + length > message.size) return null
                    expandedLength += length + 1
                    if (expandedLength > MAX_NAME_LENGTH) return null
                    cursor += length + 1
                }
            }
        }
        return null
    }

    private fun u16(bytes: ByteArray, offset: Int): Int =
        ((bytes[offset].toInt() and 0xff) shl 8) or (bytes[offset + 1].toInt() and 0xff)

    private const val HEADER_SIZE = 12
    private const val RR_FIXED_SIZE = 10
    private const val MAX_MESSAGE_SIZE = 65_535
    private const val MAX_RECORDS = 4_096
    private const val MAX_NAME_STEPS = 256
    private const val MAX_NAME_LENGTH = 255
    private const val MAX_LABEL_LENGTH = 63
    private const val TYPE_OPT = 41
}
