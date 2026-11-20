import { DomainNormalizer } from '../core/DomainNormalizer';
import { PolicyDecision } from '../core/PolicyModels';
import { PolicyEngine } from '../core/PolicyEngine';
import { EngineMonitor } from '../monitor/EngineMonitor';
import { ThreatAnalyzer } from '../threat/ThreatAnalyzer';
import { DnsDecisionCache } from './DnsDecisionCache';
import { DnsMessageParser, DnsQuestion } from './DnsMessageParser';

export type DnsEvaluation =
  | { kind: 'Forward'; question: DnsQuestion; decision: PolicyDecision; cacheHit: boolean }
  | { kind: 'Blocked'; question: DnsQuestion; decision: PolicyDecision; response: Uint8Array; cacheHit: boolean }
  | { kind: 'Rejected'; reason: string };

function putU16(target: Uint8Array, offset: number, value: number): void {
  target[offset] = (value >>> 8) & 0xff;
  target[offset + 1] = value & 0xff;
}

function nxdomainResponse(question: DnsQuestion): Uint8Array {
  const opt =
    question.ednsUdpPayloadSize !== null
      ? new Uint8Array([
          0,
          0,
          41,
          (question.ednsUdpPayloadSize >>> 8) & 0xff,
          question.ednsUdpPayloadSize & 0xff,
          0,
          0,
          question.ednsDnssecOk ? 0x80 : 0,
          0,
          0,
          0,
        ])
      : new Uint8Array(0);

  const response = new Uint8Array(12 + question.wireQuestion.length + opt.length);
  putU16(response, 0, question.id);
  const flags = 0x8000 | (question.requestFlags & (0x0100 | 0x0010)) | 0x0003;
  putU16(response, 2, flags);
  putU16(response, 4, 1);
  putU16(response, 6, 0);
  putU16(response, 8, 0);
  putU16(response, 10, opt.length === 0 ? 0 : 1);
  response.set(question.wireQuestion, 12);
  if (opt.length > 0) {
    response.set(opt, 12 + question.wireQuestion.length);
  }
  return response;
}

/** Connects validated DNS questions to the shared policy engine. */
export class DnsPolicyAdapter {
  public readonly policyEngine: PolicyEngine;
  public readonly decisionCache: DnsDecisionCache;
  public readonly threatAnalyzer: ThreatAnalyzer;
  public readonly monitor: EngineMonitor;

  constructor(
    policyEngine: PolicyEngine,
    decisionCache: DnsDecisionCache = new DnsDecisionCache(),
    threatAnalyzer: ThreatAnalyzer = new ThreatAnalyzer(),
    monitor: EngineMonitor = new EngineMonitor(),
  ) {
    this.policyEngine = policyEngine;
    this.decisionCache = decisionCache;
    this.threatAnalyzer = threatAnalyzer;
    this.monitor = monitor;
  }

  evaluate(
    packet: Uint8Array,
    appPackage: string | null = null,
    nowEpochMillis: number = Date.now(),
  ): DnsEvaluation {
    const parsed = DnsMessageParser.parse(packet);
    if (!parsed.valid) {
      this.monitor.recordRejected(parsed.reason, nowEpochMillis);
      return { kind: 'Rejected', reason: parsed.reason };
    }
    const question = parsed.question;

    if (question.dnsClass !== 1) {
      const decision: PolicyDecision = {
        action: 'ALLOW',
        reason: 'dns_class_not_filtered',
        ruleId: null,
        source: null,
        policyRevision: this.policyEngine.revision,
        expiresAtEpochMillis: null,
      };
      this.monitor.recordDecision(question.domain, appPackage, decision, nowEpochMillis);
      return { kind: 'Forward', question, decision, cacheHit: false };
    }

    const normalizedDomain = DomainNormalizer.normalize(question.domain);
    if (!normalizedDomain) {
      this.monitor.recordRejected('dns_qname_invalid_hostname', nowEpochMillis);
      return { kind: 'Rejected', reason: 'dns_qname_invalid_hostname' };
    }

    const cacheKey = {
      domain: normalizedDomain,
      appPackage,
      policyRevision: this.policyEngine.revision,
    };
    const cachedDecision = this.decisionCache.get(cacheKey, nowEpochMillis);
    const cacheHit = cachedDecision !== null;
    if (cacheHit) {
      this.monitor.recordCacheHit();
    } else {
      this.monitor.recordCacheMiss();
    }

    let decision: PolicyDecision;
    if (cachedDecision) {
      decision = cachedDecision;
    } else {
      const policyDecision = this.policyEngine.evaluate(
        { domain: normalizedDomain, appPackage },
        nowEpochMillis,
      );
      if (policyDecision.reason === 'no_matching_rule') {
        const assessment = this.threatAnalyzer.analyze(normalizedDomain);
        decision = {
          ...policyDecision,
          action: assessment.action,
          reason: assessment.reason,
          ruleId: assessment.indicatorId,
          source: assessment.source,
        };
      } else {
        decision = policyDecision;
      }
      this.decisionCache.put(
        { domain: normalizedDomain, appPackage, policyRevision: decision.policyRevision },
        decision,
        nowEpochMillis,
      );
    }

    this.monitor.recordDecision(normalizedDomain, appPackage, decision, nowEpochMillis);
    if (decision.action === 'BLOCK') {
      return {
        kind: 'Blocked',
        question,
        decision,
        response: nxdomainResponse(question),
        cacheHit,
      };
    }
    return { kind: 'Forward', question, decision, cacheHit };
  }
}
