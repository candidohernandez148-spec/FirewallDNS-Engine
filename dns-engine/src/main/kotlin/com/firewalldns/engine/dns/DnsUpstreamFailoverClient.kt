package com.firewalldns.engine.dns

/**
 * Tries configured upstreams in order. Only upstream-specific failures are
 * retried; invalid queries and local socket-protection failures are terminal.
 * Cancellation is terminal and is never retried.
 *
 * The host controls both resolver order and the maximum number of attempts.
 * This class does not choose public DNS providers or modify Android Private DNS.
 */
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
    ): DnsUpstreamResult {
        var lastFailure: DnsUpstreamResult.Failure? = null
        for (index in 0 until maxAttempts) {
            if (cancellation.isCancelled) return DnsUpstreamResult.Cancelled
            when (val result = upstreams[index].exchange(query, cancellation)) {
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
        reason.startsWith("dns_upstream_udp_") &&
            reason != "dns_upstream_udp_socket_protection_failed" ||
        reason.startsWith("dns_upstream_tcp_") &&
            reason != "dns_upstream_tcp_socket_protection_failed"
}
