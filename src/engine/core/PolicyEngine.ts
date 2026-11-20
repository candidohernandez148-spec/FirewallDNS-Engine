import { DomainNormalizer } from './DomainNormalizer';
import {
  PolicyDecision,
  PolicyRequest,
  PolicyRule,
  RULE_SOURCE_PRECEDENCE,
} from './PolicyModels';

interface CompiledRule {
  rule: PolicyRule;
  normalizedDomain: string;
}

interface Snapshot {
  revision: number;
  rules: CompiledRule[];
}

const MIN_PRIORITY = -100_000;
const MAX_PRIORITY = 100_000;
const APP_PACKAGE_PATTERN = /^[A-Za-z_][A-Za-z0-9_]*(\.[A-Za-z_][A-Za-z0-9_]*)+$/;

function matchesDomain(compiled: CompiledRule, domain: string): boolean {
  if (compiled.rule.includeSubdomains) {
    return domain === compiled.normalizedDomain || domain.endsWith(`.${compiled.normalizedDomain}`);
  }
  return domain === compiled.normalizedDomain;
}

/**
 * In-memory policy evaluator. Rule replacement is atomic; evaluations read an
 * immutable snapshot and perform no disk/network I/O or lock acquisition.
 */
export class PolicyEngine {
  private snapshot: Snapshot;

  constructor(initialRules: PolicyRule[] = []) {
    this.snapshot = {
      revision: 0,
      rules: this.compile(initialRules),
    };
  }

  /** Monotonically advances after each successfully published ruleset. */
  get revision(): number {
    return this.snapshot.revision;
  }

  getRules(): PolicyRule[] {
    return this.snapshot.rules.map((c) => ({ ...c.rule }));
  }

  /** Invalid updates are rejected as a whole; the active snapshot is retained. */
  replaceRules(newRules: PolicyRule[]): number {
    const compiled = this.compile(newRules);
    this.snapshot = {
      revision: this.snapshot.revision + 1,
      rules: compiled,
    };
    return this.snapshot.revision;
  }

  /** The explicit time parameter makes expiry behavior deterministic in tests. */
  evaluate(request: PolicyRequest, nowEpochMillis: number = Date.now()): PolicyDecision {
    const current = this.snapshot;
    const domain = DomainNormalizer.normalize(request.domain);
    if (!domain) {
      return {
        action: 'ALLOW',
        reason: 'invalid_domain_input',
        ruleId: null,
        source: null,
        policyRevision: current.revision,
        expiresAtEpochMillis: null,
      };
    }

    const reqApp = request.appPackage ?? null;
    const winner = current.rules.find((compiled) => {
      if (!compiled.rule.enabled) return false;
      if (compiled.rule.expiresAtEpochMillis !== null && compiled.rule.expiresAtEpochMillis <= nowEpochMillis) {
        return false;
      }
      if (compiled.rule.appPackage !== null && compiled.rule.appPackage !== reqApp) {
        return false;
      }
      return matchesDomain(compiled, domain);
    });

    if (winner) {
      return {
        action: winner.rule.action,
        reason: winner.rule.reason,
        ruleId: winner.rule.id,
        source: winner.rule.source,
        policyRevision: current.revision,
        expiresAtEpochMillis: winner.rule.expiresAtEpochMillis,
      };
    }

    return {
      action: 'ALLOW',
      reason: 'no_matching_rule',
      ruleId: null,
      source: null,
      policyRevision: current.revision,
      expiresAtEpochMillis: null,
    };
  }

  private compile(input: PolicyRule[]): CompiledRule[] {
    const seenIds = new Set<string>();
    const compiled: CompiledRule[] = [];

    for (const rawRule of input) {
      const rule: PolicyRule = { ...rawRule };
      if (seenIds.has(rule.id)) {
        throw new Error('Policy rule IDs must be unique');
      }
      seenIds.add(rule.id);

      if (!rule.id.trim()) {
        throw new Error('Policy rule ID must not be blank');
      }
      if (!rule.reason.trim()) {
        throw new Error('Policy rule reason must not be blank');
      }
      if (rule.source === 'HEURISTIC' && rule.action === 'BLOCK') {
        throw new Error('Heuristic policy rules must never block');
      }
      if (!Number.isInteger(rule.priority) || rule.priority < MIN_PRIORITY || rule.priority > MAX_PRIORITY) {
        throw new Error(`Policy rule priority must be between ${MIN_PRIORITY} and ${MAX_PRIORITY}`);
      }
      const normalizedDomain = DomainNormalizer.normalize(rule.domain);
      if (!normalizedDomain) {
        throw new Error(`Invalid domain in policy rule '${rule.id}'`);
      }
      if (rule.appPackage !== null && !APP_PACKAGE_PATTERN.test(rule.appPackage)) {
        throw new Error(`Invalid Android package name in policy rule '${rule.id}'`);
      }
      compiled.push({ rule, normalizedDomain });
    }

    compiled.sort((a, b) => {
      if (a.rule.priority !== b.rule.priority) return b.rule.priority - a.rule.priority;
      const precDiff = RULE_SOURCE_PRECEDENCE[b.rule.source] - RULE_SOURCE_PRECEDENCE[a.rule.source];
      if (precDiff !== 0) return precDiff;
      if (a.normalizedDomain.length !== b.normalizedDomain.length) {
        return b.normalizedDomain.length - a.normalizedDomain.length;
      }
      const aExact = a.rule.includeSubdomains ? 0 : 1;
      const bExact = b.rule.includeSubdomains ? 0 : 1;
      if (aExact !== bExact) return bExact - aExact;
      const aHasPkg = a.rule.appPackage !== null ? 1 : 0;
      const bHasPkg = b.rule.appPackage !== null ? 1 : 0;
      if (aHasPkg !== bHasPkg) return bHasPkg - aHasPkg;
      return a.rule.id < b.rule.id ? -1 : a.rule.id > b.rule.id ? 1 : 0;
    });

    return compiled;
  }
}
