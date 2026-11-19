package com.firewalldns.engine.dns

/**
 * Tries configured upstreams in order. A failed resolver does not prevent the
 * next resolver from answering; cancellation is terminal and is never retried.
 *
 * Configure the list explicitly in the host. This class does not choose public
 * DNS providers, change Android Private DNS, or perform background health checks.
 */
class DnsUpstreamFailoverClient(
    private val upstreams: List<DnsUpstreamClient>,
) {
    init {
        require(upstreams.isNotEmpty()) { "At least one DNS upstream is required" }
    }

    fun exchange(query: ByteArray): DnsUpstreamResult =
        exchange(query, DnsExchangeCancellation())

    fun exchange(
        query: ByteArray,
        cancellation: DnsExchangeCancellation,
    ): DnsUpstreamResult {
        var lastFailure: DnsUpstreamResult.Failure? = null
        for (upstream in upstreams) {
            if (cancellation.isCancelled) return DnsUpstreamResult.Cancelled
            when (val result = upstream.exchange(query, cancellation)) {
                is DnsUpstreamResult.Success -> return result
                DnsUpstreamResult.Cancelled -> return DnsUpstreamResult.Cancelled
                is DnsUpstreamResult.Failure -> lastFailure = result
            }
        }
        return lastFailure ?: DnsUpstreamResult.Failure("dns_upstream_no_resolver_attempted")
    }
}
