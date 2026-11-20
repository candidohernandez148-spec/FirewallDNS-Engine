import { PolicyAction, RuleSource } from '../core/PolicyModels';

export type ThreatCategory = 'ADVERTISING' | 'TRACKING' | 'MALWARE' | 'PHISHING' | 'SUSPICIOUS';

export interface ThreatIndicator {
  id: string;
  domain: string;
  includeSubdomains: boolean;
  category: ThreatCategory;
  confidence: number;
  action: PolicyAction;
  source: RuleSource;
  reason: string;
}

export interface ThreatSignal {
  id: string;
  category: ThreatCategory;
  confidence: number;
  evidence: string;
  source: RuleSource;
}

export interface ThreatAssessment {
  domain: string | null;
  action: PolicyAction;
  riskScore: number;
  confidence: number;
  reason: string;
  indicatorId: string | null;
  source: RuleSource | null;
  signals: ThreatSignal[];
}
