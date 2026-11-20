import { DomainNormalizer } from '../core/DomainNormalizer';
import { ThreatAssessment, ThreatIndicator, ThreatSignal } from './ThreatModels';

interface CompiledIndicator {
  indicator: ThreatIndicator;
  domain: string;
}

const MIN_TRUSTED_BLOCK_CONFIDENCE = 90;

export const DEFAULT_INDICATORS: ThreatIndicator[] = [
  { id: 'ads-doubleclick', domain: 'doubleclick.net', includeSubdomains: true, category: 'ADVERTISING', confidence: 99, action: 'BLOCK', source: 'BUILTIN', reason: 'known_ad_delivery_domain' },
  { id: 'ads-googlesyndication', domain: 'googlesyndication.com', includeSubdomains: true, category: 'ADVERTISING', confidence: 99, action: 'BLOCK', source: 'BUILTIN', reason: 'known_ad_delivery_domain' },
  { id: 'ads-googleadservices', domain: 'googleadservices.com', includeSubdomains: true, category: 'ADVERTISING', confidence: 98, action: 'BLOCK', source: 'BUILTIN', reason: 'known_ad_delivery_domain' },
  { id: 'ads-adnxs', domain: 'adnxs.com', includeSubdomains: true, category: 'ADVERTISING', confidence: 97, action: 'BLOCK', source: 'BUILTIN', reason: 'known_ad_exchange_domain' },
  { id: 'ads-taboola', domain: 'taboola.com', includeSubdomains: true, category: 'ADVERTISING', confidence: 96, action: 'BLOCK', source: 'BUILTIN', reason: 'known_recommendation_ad_domain' },
  { id: 'ads-outbrain', domain: 'outbrain.com', includeSubdomains: true, category: 'ADVERTISING', confidence: 96, action: 'BLOCK', source: 'BUILTIN', reason: 'known_recommendation_ad_domain' },
  { id: 'track-google-analytics', domain: 'google-analytics.com', includeSubdomains: true, category: 'TRACKING', confidence: 88, action: 'OBSERVE', source: 'BUILTIN', reason: 'known_analytics_domain' },
  { id: 'track-tag-manager', domain: 'googletagmanager.com', includeSubdomains: true, category: 'TRACKING', confidence: 82, action: 'OBSERVE', source: 'BUILTIN', reason: 'known_tag_management_domain' },
  { id: 'track-facebook-pixel', domain: 'pixel.facebook.com', includeSubdomains: true, category: 'TRACKING', confidence: 88, action: 'OBSERVE', source: 'BUILTIN', reason: 'known_social_tracking_pixel' },
  { id: 'track-facebook-connect', domain: 'connect.facebook.net', includeSubdomains: true, category: 'TRACKING', confidence: 82, action: 'OBSERVE', source: 'BUILTIN', reason: 'social_sdk_tracking_endpoint' },
];

export const DEFAULT_SAFE_DOMAINS: string[] = [
  'whatsapp.com',
  'whatsapp.net',
  'facebook.com',
  'fbcdn.net',
  'youtube.com',
  'google.com',
  'gstatic.com',
  'googleapis.com',
  'android.com',
];

const TRACKING_TERMS = ['track', 'tracker', 'tracking', 'pixel', 'analytics', 'telemetry', 'metrics', 'beacon'];

/**
 * Local, explainable domain reputation. Trusted indicators may block; lexical
 * heuristics only OBSERVE and therefore never block on a weak signal alone.
 */
export class ThreatAnalyzer {
  private compiledIndicators: CompiledIndicator[] = [];
  private normalizedSafeDomains: string[] = [];

  constructor(
    indicators: ThreatIndicator[] = DEFAULT_INDICATORS,
    safeDomains: string[] = DEFAULT_SAFE_DOMAINS,
  ) {
    this.replaceDatabase(indicators, safeDomains);
  }

  replaceDatabase(indicators: ThreatIndicator[], safeDomains: string[]): void {
    const seenIds = new Set<string>();
    const compiled: CompiledIndicator[] = [];

    for (const raw of indicators) {
      const indicator = { ...raw };
      if (seenIds.has(indicator.id)) {
        throw new Error('Threat indicator IDs must be unique');
      }
      seenIds.add(indicator.id);
      if (!indicator.id.trim()) {
        throw new Error('Threat indicator ID must not be blank');
      }
      if (!indicator.reason.trim()) {
        throw new Error('Threat indicator reason must not be blank');
      }
      if (indicator.confidence < 0 || indicator.confidence > 100) {
        throw new Error('Threat confidence must be between 0 and 100');
      }
      if (
        indicator.action === 'BLOCK' &&
        (indicator.confidence < MIN_TRUSTED_BLOCK_CONFIDENCE || indicator.source === 'HEURISTIC')
      ) {
        throw new Error('Blocking indicators require high-confidence curated provenance');
      }
      const norm = DomainNormalizer.normalize(indicator.domain);
      if (!norm) {
        throw new Error(`Invalid threat indicator domain '${indicator.id}'`);
      }
      compiled.push({ indicator, domain: norm });
    }

    compiled.sort((a, b) => {
      if (a.domain.length !== b.domain.length) return b.domain.length - a.domain.length;
      if (a.indicator.confidence !== b.indicator.confidence) {
        return b.indicator.confidence - a.indicator.confidence;
      }
      return a.indicator.id < b.indicator.id ? -1 : a.indicator.id > b.indicator.id ? 1 : 0;
    });

    const normalizedSafe: string[] = [];
    for (const domain of safeDomains) {
      const norm = DomainNormalizer.normalize(domain);
      if (!norm) {
        throw new Error(`Invalid safe domain '${domain}'`);
      }
      normalizedSafe.push(norm);
    }

    this.compiledIndicators = compiled;
    this.normalizedSafeDomains = normalizedSafe;
  }

  getIndicators(): ThreatIndicator[] {
    return this.compiledIndicators.map((c) => ({ ...c.indicator }));
  }

  getSafeDomains(): string[] {
    return [...this.normalizedSafeDomains];
  }

  analyze(domainInput: string): ThreatAssessment {
    const domain = DomainNormalizer.normalize(domainInput);
    if (!domain) {
      return {
        domain: null,
        action: 'ALLOW',
        riskScore: 0,
        confidence: 0,
        reason: 'invalid_domain_input',
        indicatorId: null,
        source: null,
        signals: [],
      };
    }

    const matched = this.compiledIndicators.find((compiled) => {
      if (compiled.indicator.includeSubdomains) {
        return domain === compiled.domain || domain.endsWith(`.${compiled.domain}`);
      }
      return domain === compiled.domain;
    });

    if (matched) {
      const ind = matched.indicator;
      const signal: ThreatSignal = {
        id: ind.id,
        category: ind.category,
        confidence: ind.confidence,
        evidence: ind.reason,
        source: ind.source,
      };
      return {
        domain,
        action: ind.action,
        riskScore: ind.confidence,
        confidence: ind.confidence,
        reason: ind.reason,
        indicatorId: ind.id,
        source: ind.source,
        signals: [signal],
      };
    }

    if (this.normalizedSafeDomains.some((safe) => domain === safe || domain.endsWith(`.${safe}`))) {
      return {
        domain,
        action: 'ALLOW',
        riskScore: 0,
        confidence: 100,
        reason: 'trusted_domain_allowlist',
        indicatorId: null,
        source: null,
        signals: [],
      };
    }

    const labels = domain.split('.');
    const signals: ThreatSignal[] = [];

    if (
      labels.some(
        (label) =>
          label === 'ad' ||
          label === 'ads' ||
          label.startsWith('ads-') ||
          label.endsWith('-ads') ||
          label.includes('advert') ||
          label.includes('banner'),
      )
    ) {
      signals.push({
        id: 'heuristic_advertising_label',
        category: 'ADVERTISING',
        confidence: 35,
        evidence: 'domain_label_contains_advertising_term',
        source: 'HEURISTIC',
      });
    }

    if (labels.some((label) => TRACKING_TERMS.some((term) => label.includes(term)))) {
      signals.push({
        id: 'heuristic_tracking_label',
        category: 'TRACKING',
        confidence: 30,
        evidence: 'domain_label_contains_tracking_term',
        source: 'HEURISTIC',
      });
    }

    if (signals.length === 0) {
      return {
        domain,
        action: 'ALLOW',
        riskScore: 0,
        confidence: 0,
        reason: 'no_threat_signals',
        indicatorId: null,
        source: null,
        signals: [],
      };
    }

    const strongest = signals.reduce((best, cur) => (cur.confidence > best.confidence ? cur : best));
    const totalScore = Math.min(
      100,
      signals.reduce((sum, s) => sum + s.confidence, 0),
    );

    return {
      domain,
      action: 'OBSERVE',
      riskScore: totalScore,
      confidence: strongest.confidence,
      reason: 'heuristic_signals_require_observation',
      indicatorId: null,
      source: 'HEURISTIC',
      signals,
    };
  }
}
