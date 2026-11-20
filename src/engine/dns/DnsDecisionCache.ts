import { PolicyDecision } from '../core/PolicyModels';

export interface DnsDecisionCacheKey {
  domain: string;
  appPackage: string | null;
  policyRevision: number;
}

interface CacheEntry {
  decision: PolicyDecision;
  expiresAtEpochMillis: number;
}

const DEFAULT_MAX_ENTRIES = 4_096;
const DEFAULT_TTL_MILLIS = 30_000;

function serializeKey(key: DnsDecisionCacheKey): string {
  return `${key.policyRevision}|${key.appPackage ?? ''}|${key.domain}`;
}

/**
 * Bounded, non-blocking decision cache scoped to a policy snapshot revision.
 */
export class DnsDecisionCache {
  private readonly maxEntries: number;
  private readonly ttlMillis: number;
  private readonly entries = new Map<string, CacheEntry>();

  constructor(maxEntries: number = DEFAULT_MAX_ENTRIES, ttlMillis: number = DEFAULT_TTL_MILLIS) {
    if (maxEntries <= 0) throw new Error('maxEntries must be positive');
    if (ttlMillis <= 0) throw new Error('ttlMillis must be positive');
    this.maxEntries = maxEntries;
    this.ttlMillis = ttlMillis;
  }

  get(key: DnsDecisionCacheKey, nowEpochMillis: number): PolicyDecision | null {
    const serialized = serializeKey(key);
    const entry = this.entries.get(serialized);
    if (!entry) return null;
    if (entry.expiresAtEpochMillis <= nowEpochMillis) {
      this.entries.delete(serialized);
      return null;
    }
    return entry.decision;
  }

  put(key: DnsDecisionCacheKey, decision: PolicyDecision, nowEpochMillis: number): void {
    const ruleExpiry = decision.expiresAtEpochMillis ?? Number.MAX_SAFE_INTEGER;
    const expiry = Math.min(nowEpochMillis + this.ttlMillis, ruleExpiry);
    if (expiry <= nowEpochMillis) return;

    const serialized = serializeKey(key);
    if (this.entries.has(serialized)) {
      this.entries.set(serialized, { decision, expiresAtEpochMillis: expiry });
      return;
    }

    if (this.entries.size >= this.maxEntries) {
      for (const [k, entry] of this.entries.entries()) {
        if (entry.expiresAtEpochMillis <= nowEpochMillis) {
          this.entries.delete(k);
        }
      }
      if (this.entries.size >= this.maxEntries) {
        const oldestKey = this.entries.keys().next().value;
        if (oldestKey !== undefined) {
          this.entries.delete(oldestKey);
        }
      }
    }

    this.entries.set(serialized, { decision, expiresAtEpochMillis: expiry });
  }

  clear(): void {
    this.entries.clear();
  }

  get size(): number {
    return this.entries.size;
  }
}
