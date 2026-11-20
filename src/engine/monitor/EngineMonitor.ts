import { PolicyDecision, RuleSource } from '../core/PolicyModels';

export type EngineEventType = 'DNS_BLOCKED' | 'DNS_OBSERVED' | 'DNS_ALLOWED' | 'DNS_REJECTED';

export interface EngineEvent {
  sequence: number;
  timestampEpochMillis: number;
  type: EngineEventType;
  reason: string;
  source: RuleSource | null;
  domain: string | null;
  appPackage: string | null;
}

export interface EngineMetricsSnapshot {
  decisions: number;
  blocked: number;
  observed: number;
  allowed: number;
  rejected: number;
  cacheHits: number;
  cacheMisses: number;
  eventsDropped: number;
  queuedEvents: number;
}

const DEFAULT_QUEUE_CAPACITY = 512;

/**
 * Bounded local telemetry. Recording never performs disk/network I/O and never
 * waits for a consumer. Domain/package details are redacted by default.
 */
export class EngineMonitor {
  private readonly queueCapacity: number;
  public captureDomains: boolean;
  public captureAppPackages: boolean;

  private events: EngineEvent[] = [];
  private sequence = 0;

  private decisions = 0;
  private blocked = 0;
  private observed = 0;
  private allowed = 0;
  private rejected = 0;
  private cacheHits = 0;
  private cacheMisses = 0;
  private eventsDropped = 0;

  constructor(
    queueCapacity: number = DEFAULT_QUEUE_CAPACITY,
    captureDomains: boolean = false,
    captureAppPackages: boolean = false,
  ) {
    if (queueCapacity <= 0) {
      throw new Error('queueCapacity must be positive');
    }
    this.queueCapacity = queueCapacity;
    this.captureDomains = captureDomains;
    this.captureAppPackages = captureAppPackages;
  }

  recordDecision(
    domain: string | null,
    appPackage: string | null,
    decision: PolicyDecision,
    timestampEpochMillis: number,
  ): void {
    this.decisions++;
    let type: EngineEventType;
    switch (decision.action) {
      case 'BLOCK':
        this.blocked++;
        type = 'DNS_BLOCKED';
        break;
      case 'OBSERVE':
        this.observed++;
        type = 'DNS_OBSERVED';
        break;
      case 'ALLOW':
        this.allowed++;
        type = 'DNS_ALLOWED';
        break;
    }

    this.offer({
      sequence: ++this.sequence,
      timestampEpochMillis,
      type,
      reason: decision.reason,
      source: decision.source,
      domain: this.captureDomains ? domain : null,
      appPackage: this.captureAppPackages ? appPackage : null,
    });
  }

  recordRejected(reason: string, timestampEpochMillis: number): void {
    this.rejected++;
    this.offer({
      sequence: ++this.sequence,
      timestampEpochMillis,
      type: 'DNS_REJECTED',
      reason,
      source: null,
      domain: null,
      appPackage: null,
    });
  }

  recordCacheHit(): void {
    this.cacheHits++;
  }

  recordCacheMiss(): void {
    this.cacheMisses++;
  }

  pollEvent(): EngineEvent | null {
    return this.events.shift() ?? null;
  }

  drainEvents(maxCount: number): EngineEvent[] {
    if (maxCount < 0) throw new Error('maxCount must not be negative');
    const count = Math.min(maxCount, this.events.length);
    return this.events.splice(0, count);
  }

  peekEvents(): EngineEvent[] {
    return [...this.events];
  }

  clearEvents(): void {
    this.events = [];
  }

  resetAll(): void {
    this.events = [];
    this.sequence = 0;
    this.decisions = 0;
    this.blocked = 0;
    this.observed = 0;
    this.allowed = 0;
    this.rejected = 0;
    this.cacheHits = 0;
    this.cacheMisses = 0;
    this.eventsDropped = 0;
  }

  snapshot(): EngineMetricsSnapshot {
    return {
      decisions: this.decisions,
      blocked: this.blocked,
      observed: this.observed,
      allowed: this.allowed,
      rejected: this.rejected,
      cacheHits: this.cacheHits,
      cacheMisses: this.cacheMisses,
      eventsDropped: this.eventsDropped,
      queuedEvents: this.events.length,
    };
  }

  private offer(event: EngineEvent): void {
    if (this.events.length >= this.queueCapacity) {
      this.eventsDropped++;
      return;
    }
    this.events.push(event);
  }
}
