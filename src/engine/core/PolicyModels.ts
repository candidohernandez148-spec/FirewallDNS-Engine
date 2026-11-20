/** OBSERVE records a signal but does not block the request. */
export type PolicyAction = 'BLOCK' | 'OBSERVE' | 'ALLOW';

/** Provenance of a policy or threat signal; HEURISTIC is computed, never learned from traffic. */
export type RuleSource = 'HEURISTIC' | 'BUILTIN' | 'MANAGED' | 'USER';

export const RULE_SOURCE_PRECEDENCE: Record<RuleSource, number> = {
  HEURISTIC: 1,
  BUILTIN: 2,
  MANAGED: 3,
  USER: 4,
};

export interface PolicyRule {
  id: string;
  domain: string;
  includeSubdomains: boolean;
  appPackage: string | null;
  action: PolicyAction;
  source: RuleSource;
  priority: number;
  reason: string;
  enabled: boolean;
  /** Unix epoch milliseconds; null means no expiry. */
  expiresAtEpochMillis: number | null;
}

export interface PolicyRequest {
  domain: string;
  appPackage?: string | null;
}

export interface PolicyDecision {
  action: PolicyAction;
  reason: string;
  ruleId: string | null;
  source: RuleSource | null;
  policyRevision: number;
  expiresAtEpochMillis: number | null;
}
