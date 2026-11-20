import { buildPositiveDnsResponse, DnsMessageParser, DnsQuestion } from './DnsMessageParser';
import { DnsResponseCache, DnsUpstreamResponse } from './DnsResponseCache';
import { DnsUpstreamResponseValidator } from './DnsUpstreamResponseValidator';

export interface DnsUpstreamConfig {
  host: string;
  port?: number;
  timeoutMillis?: number;
  mode?: 'doh' | 'loopback' | 'silent';
}

export type DnsUpstreamResult =
  | { kind: 'Success'; response: DnsUpstreamResponse }
  | { kind: 'Failure'; reason: string }
  | { kind: 'Cancelled' };

const DOH_ENDPOINTS: Record<string, string> = {
  '1.1.1.1': 'https://cloudflare-dns.com/dns-query',
  '1.0.0.1': 'https://1.0.0.1/dns-query',
  '8.8.8.8': 'https://dns.google/dns-query',
  '8.8.4.4': 'https://dns.google/dns-query',
  '9.9.9.9': 'https://dns.quad9.net:5053/dns-query',
};

function u16(bytes: Uint8Array, offset: number): number {
  return ((bytes[offset] & 0xff) << 8) | (bytes[offset + 1] & 0xff);
}

/**
 * Bounded async DNS upstream client. Uses real RFC 8484 DNS-over-HTTPS wire messages
 * for public numeric resolvers (1.1.1.1, 8.8.8.8, 9.9.9.9), an in-process loopback
 * responder for local engine benchmarks, or a silent blackhole for failover timeout tests.
 */
export class DnsUpstreamClient {
  public readonly config: Required<DnsUpstreamConfig>;
  public readonly responseCache: DnsResponseCache;

  constructor(config: DnsUpstreamConfig, responseCache: DnsResponseCache = new DnsResponseCache()) {
    this.config = {
      host: config.host,
      port: config.port ?? 53,
      timeoutMillis: config.timeoutMillis ?? 2_000,
      mode: config.mode ?? (config.host === '127.0.0.1' || config.host === '::1' ? 'loopback' : 'doh'),
    };
    this.responseCache = responseCache;
  }

  async exchange(query: Uint8Array, signal?: AbortSignal): Promise<DnsUpstreamResult> {
    if (signal?.aborted) return { kind: 'Cancelled' };

    const parsed = DnsMessageParser.parse(query);
    if (!parsed.valid) {
      return { kind: 'Failure', reason: parsed.reason };
    }
    const question = parsed.question;
    const upstreamIdentity = `${this.config.host}:${this.config.port}`;

    const cached = this.responseCache.get(upstreamIdentity, query, performance.now());
    if (cached) {
      return { kind: 'Success', response: cached };
    }

    let result: DnsUpstreamResult;
    if (this.config.mode === 'loopback') {
      const response = buildPositiveDnsResponse(query, 60);
      const invalidReason = this.validateResponse(query, question, response);
      result = invalidReason
        ? { kind: 'Failure', reason: invalidReason }
        : { kind: 'Success', response: { message: response, transport: 'UDP' } };
    } else if (this.config.mode === 'silent') {
      result = await this.waitTimeout(this.config.timeoutMillis, signal);
    } else {
      result = await this.exchangeDoh(query, question, signal);
    }

    if (result.kind === 'Success') {
      this.responseCache.put(upstreamIdentity, query, result.response.message, performance.now());
    }
    return result;
  }

  private waitTimeout(timeoutMs: number, signal?: AbortSignal): Promise<DnsUpstreamResult> {
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        signal?.removeEventListener('abort', onAbort);
        resolve({ kind: 'Failure', reason: 'dns_upstream_udp_timeout' });
      }, timeoutMs);
      const onAbort = () => {
        clearTimeout(timer);
        resolve({ kind: 'Cancelled' });
      };
      if (signal) {
        if (signal.aborted) {
          clearTimeout(timer);
          resolve({ kind: 'Cancelled' });
        } else {
          signal.addEventListener('abort', onAbort, { once: true });
        }
      }
    });
  }

  private async exchangeDoh(
    query: Uint8Array,
    question: DnsQuestion,
    externalSignal?: AbortSignal,
  ): Promise<DnsUpstreamResult> {
    const endpoint = DOH_ENDPOINTS[this.config.host] ?? `https://${this.config.host}/dns-query`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort('timeout'), this.config.timeoutMillis);
    const onExternalAbort = () => controller.abort('cancelled');
    externalSignal?.addEventListener('abort', onExternalAbort, { once: true });

    try {
      const resp = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/dns-message',
          Accept: 'application/dns-message',
        },
        body: query.slice().buffer,
        signal: controller.signal,
      });
      if (!resp.ok) {
        return { kind: 'Failure', reason: `dns_upstream_http_${resp.status}` };
      }
      const buf = new Uint8Array(await resp.arrayBuffer());
      const invalidReason = this.validateResponse(query, question, buf);
      if (invalidReason) {
        return { kind: 'Failure', reason: invalidReason };
      }
      return { kind: 'Success', response: { message: buf, transport: 'DOH' } };
    } catch (err) {
      if (externalSignal?.aborted || controller.signal.reason === 'cancelled') {
        return { kind: 'Cancelled' };
      }
      if (controller.signal.reason === 'timeout' || (err instanceof DOMException && err.name === 'AbortError')) {
        return { kind: 'Failure', reason: 'dns_upstream_udp_timeout' };
      }
      return { kind: 'Failure', reason: 'dns_upstream_udp_io_error' };
    } finally {
      clearTimeout(timeoutId);
      externalSignal?.removeEventListener('abort', onExternalAbort);
    }
  }

  private validateResponse(query: Uint8Array, question: DnsQuestion, response: Uint8Array): string | null {
    if (response.length < 12) return 'dns_upstream_response_header_truncated';
    if (u16(response, 0) !== question.id) return 'dns_upstream_transaction_id_mismatch';
    const responseFlags = u16(response, 2);
    if ((responseFlags & 0x8000) === 0) return 'dns_upstream_packet_is_not_response';
    if ((responseFlags & 0x7800) !== (question.requestFlags & 0x7800)) {
      return 'dns_upstream_opcode_mismatch';
    }
    if (u16(query, 0) !== question.id) return 'dns_upstream_query_mismatch';
    return DnsUpstreamResponseValidator.validate(response, question.wireQuestion);
  }
}
