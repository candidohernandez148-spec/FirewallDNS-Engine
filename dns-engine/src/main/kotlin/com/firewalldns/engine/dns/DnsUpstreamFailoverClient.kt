package com.firewalldns.engine.dns

data class DnsUpstreamAttempt(
    val resolverIndex: Int,
    val elapsedNanos: Long,
    val result: DnsUpstreamResult,
)

class DnsUpstreamFailoverClient(
    private val upstreams: List<DnsUpstreamClient>,
    private val maxAttempts: Int = upstreams.size,
) {
    init {
        require(upstreams.isNotEmpty()) { "At least one DNS upstream is required" }
        require(maxAttempts in 1..upstreams.size) {
            "Maximum attempts must be between 1 and the configured upstream count"
        }
    }

    fun exchange(query: ByteArray): DnsUpstreamResult =
        exchange(query, DnsExchangeCancellation())

    fun exchange(
        query: ByteArray,
        cancellation: DnsExchangeCancellation,
    ): DnsUpstreamResult = exchange(query, cancellation, null)

    fun exchange(
        query: ByteArray,
        cancellation: DnsExchangeCancellation,
        onAttempt: ((DnsUpstreamAttempt) -> Unit)?,
    ): DnsUpstreamResult {
        var lastFailure: DnsUpstreamResult.Failure? = null
        for (index in 0 until maxAttempts) {
            if (cancellation.isCancelled) return DnsUpstreamResult.Cancelled
            val started = System.nanoTime()
            val attemptResult = upstreams[index].exchange(query, cancellation)
            val elapsed = System.nanoTime() - started
            try { onAttempt?.invoke(DnsUpstreamAttempt(index, elapsed, attemptResult)) } catch (_: Throwable) {
            }
            when (val result = attemptResult) {
                is DnsUpstreamResult.Success -> return result
                DnsUpstreamResult.Cancelled -> return DnsUpstreamResult.Cancelled
                is DnsUpstreamResult.Failure -> {
                    if (!isRetryableUpstreamFailure(result.reason)) return result
                    lastFailure = result
                }
            }
        }
        return lastFailure ?: DnsUpstreamResult.Failure("dns_upstream_no_resolver_attempted")
    }

    private fun isRetryableUpstreamFailure(reason: String): Boolean =
        reason in RETRYABLE_FAILURES ||
            reason.startsWith("dns_upstream_response_") ||
            reason in RESPONSE_VALIDATION_FAILURES ||
            reason in RESPONSE_MISMATCH_FAILURES

    private companion object {
        val RETRYABLE_FAILURES = setOf(
            "dns_upstream_udp_timeout",
            "dns_upstream_udp_io_error",
            "dns_upstream_tcp_timeout",
            "dns_upstream_tcp_io_error",
            "dns_upstream_tcp_response_incomplete",
            "dns_upstream_tcp_frame_too_short",
            "dns_upstream_tcp_response_truncated",
        )
        val RESPONSE_VALIDATION_FAILURES = setOf(
            "dns_upstream_question_count_unsupported",
            "dns_upstream_question_malformed",
            "dns_upstream_question_mismatch",
            "dns_upstream_record_count_unsupported",
            "dns_upstream_record_name_malformed",
            "dns_upstream_record_header_truncated",
            "dns_upstream_record_data_truncated",
            "dns_upstream_edns_record_position_invalid",
            "dns_upstream_edns_owner_invalid",
            "dns_upstream_edns_option_header_truncated",
            "dns_upstream_edns_option_data_truncated",
        )
        val RESPONSE_MISMATCH_FAILURES = setOf(
            "dns_upstream_transaction_id_mismatch",
            "dns_upstream_packet_is_not_response",
            "dns_upstream_opcode_mismatch",
            "dns_upstream_query_mismatch",
            "dns_upstream_question_mismatch",
        )
    }
}
