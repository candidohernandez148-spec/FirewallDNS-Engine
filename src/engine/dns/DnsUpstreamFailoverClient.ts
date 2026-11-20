import { DnsUpstreamClient, DnsUpstreamResult } from './DnsUpstreamClient';

export interface DnsUpstreamAttempt {
  resolverIndex: number;
  elapsedUs: number;
  result: DnsUpstreamResult;
}

const RETRYABLE_FAILURES = new Set([
  'dns_upstream_udp_timeout',
  'dns_upstream_udp_io_error',
  'dns_upstream_tcp_timeout',
  'dns_upstream_tcp_io_error',
  'dns_upstream_tcp_response_incomplete',
  'dns_upstream_tcp_frame_too_short',
  'dns_upstream_tcp_response_truncated',
  'dns_upstream_question_count_unsupported',
  'dns_upstream_question_malformed',
  'dns_upstream_question_mismatch',
  'dns_upstream_record_count_unsupported',
  'dns_upstream_record_name_malformed',
  'dns_upstream_record_header_truncated',
  'dns_upstream_record_data_truncated',
  'dns_upstream_edns_record_position_invalid',
  'dns_upstream_edns_owner_invalid',
  'dns_upstream_edns_option_header_truncated',
  'dns_upstream_edns_option_data_truncated',
  'dns_upstream_transaction_id_mismatch',
  'dns_upstream_packet_is_not_response',
  'dns_upstream_opcode_mismatch',
  'dns_upstream_query_mismatch',
]);

function isRetryableUpstreamFailure(reason: string): boolean {
  return RETRYABLE_FAILURES.has(reason) || reason.startsWith('dns_upstream_response_');
}

/**
 * Tries configured upstreams in order. Only upstream-specific failures are
 * retried; invalid queries and cancellations are terminal.
 */
export class DnsUpstreamFailoverClient {
  private readonly upstreams: DnsUpstreamClient[];
  private readonly maxAttempts: number;

  constructor(upstreams: DnsUpstreamClient[], maxAttempts: number = upstreams.length) {
    if (upstreams.length === 0) {
      throw new Error('At least one DNS upstream is required');
    }
    if (maxAttempts < 1 || maxAttempts > upstreams.length) {
      throw new Error('Maximum attempts must be between 1 and the configured upstream count');
    }
    this.upstreams = upstreams;
    this.maxAttempts = maxAttempts;
  }

  async exchange(
    query: Uint8Array,
    signal?: AbortSignal,
    onAttempt?: (attempt: DnsUpstreamAttempt) => void,
  ): Promise<DnsUpstreamResult> {
    let lastFailure: DnsUpstreamResult | null = null;
    for (let index = 0; index < this.maxAttempts; index++) {
      if (signal?.aborted) return { kind: 'Cancelled' };
      const started = performance.now();
      const attemptResult = await this.upstreams[index].exchange(query, signal);
      const elapsedUs = Math.max(0, Math.round((performance.now() - started) * 1000));
      try {
        onAttempt?.({ resolverIndex: index, elapsedUs, result: attemptResult });
      } catch {
        // Observability must never change the resolver's decision.
      }
      if (attemptResult.kind === 'Success') return attemptResult;
      if (attemptResult.kind === 'Cancelled') return attemptResult;
      if (!isRetryableUpstreamFailure(attemptResult.reason)) return attemptResult;
      lastFailure = attemptResult;
    }
    return lastFailure ?? { kind: 'Failure', reason: 'dns_upstream_no_resolver_attempted' };
  }
}
