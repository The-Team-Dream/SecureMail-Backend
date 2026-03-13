// ─────────────────────────────────────────────────────────────────────────────
// detection/rule-engine/detection-context.ts
//
// Detection Context — shared state object flowing through ALL rule evaluations.
//
// The DetectionContext is the single source of truth during a pipeline run.
// Rules read signals from it and write their RuleResult back into it.
// This enables:
//   - Rule dependencies  (rule B reads result of rule A)
//   - Rule correlation   (correlation engine reads all results at the end)
//   - Attack pattern detection (multiple rule hits → amplified score)
//   - Full explainability (every signal stored for forensics)
// ─────────────────────────────────────────────────────────────────────────────

import { ParsedEmail }   from '../../email-parser/email-parser.service';
import { AuthResult }    from '../../authentication/authentication.service';

// ─── RuleResult — output of a single rule evaluation ─────────────────────────
export interface RuleResult {
  ruleId:      string;           // e.g. 'spf_dkim_fail'
  category:    RuleCategory;
  severity:    RuleSeverity;
  triggered:   boolean;
  score:       number;           // contribution to phishing/spam score
  confidence:  number;           // 0-100
  explanation: string;           // human-readable reason shown to user
}

export type RuleCategory =
  | 'sender'
  | 'content'
  | 'url'
  | 'headers'
  | 'attachment'
  | 'authentication'
  | 'reputation'
  | 'behavioral'
  | 'advanced';

export type RuleSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// ─── ReputationSignals — populated by ReputationEngine ───────────────────────
export interface ReputationSignals {
  senderIpReputation:   'good' | 'bad' | 'neutral' | 'unknown';
  domainReputation:     'good' | 'bad' | 'neutral' | 'unknown';
  urlReputation:        'good' | 'bad' | 'neutral' | 'unknown';
  attachmentHashReputation: 'clean' | 'malicious' | 'suspicious' | 'unknown';
  overallThreatScore:   number;   // 0-100
  details:              string;
}

// ─── BehaviorSignals — populated by BehaviorAnalysisEngine ───────────────────
export interface BehaviorSignals {
  previousEmailCount: number;
  typicalTopic:       string;
  behaviorScore:      number;    // 0-100, higher = more anomalous
  anomalyFlag:        boolean;
  anomalyDescription: string;
}

// ─── MalwareSignals — populated by MalwareAnalysisEngine (existing service) ──
export interface MalwareSignals {
  verdict:  string;   // clean | suspicious | malicious
  score:    number;   // 0-100
  severity: string;   // Low | Medium | High | Critical
  report?:  string;   // JSON details from sandbox
}

// ─── CorrelationResult — populated by CorrelationEngine ──────────────────────
export interface CorrelationResult {
  patterns:       string[];     // attack pattern names detected
  bonusScore:     number;       // extra score added by correlation
  description:    string;
}

// ─── AI signals — populated by AiAgentService after the pipeline runs ─────────
// The AI agent NEVER overrides rule results.
// It enriches explainability only.
export interface AiSignals {
  verdict?:             string;    // AI-inferred verdict (informational only)
  confidence?:          number;    // 0-100
  summary?:             string;    // one-paragraph email summary
  explanation?:         string;    // AI reasoning for threat classification
  replySuggestions?:    string[];  // suggested safe replies
  isCampaign?:          boolean;   // AI detected this is part of a campaign
  campaignDescription?: string;
  behavioralAnomaly?:   boolean;
  anomalyDescription?:  string;
  recommendation?:      string;
}

// ─── DetectionContext ─────────────────────────────────────────────────────────
export class DetectionContext {
  // ── Input signals (set before rules run) ──────────────────────────────────
  parsedEmail:  ParsedEmail;
  authResult:   AuthResult;
  reputation:   ReputationSignals;
  behavior:     BehaviorSignals;
  malware:      MalwareSignals | null = null;

  // ── Rule results (written by individual rules) ────────────────────────────
  ruleResults: Map<string, RuleResult> = new Map();

  // ── Correlation results (written by CorrelationEngine) ───────────────────
  correlation: CorrelationResult = {
    patterns:    [],
    bonusScore:  0,
    description: '',
  };

  // ── AI signals (written by AiAgentService — informational only) ───────────
  // AI NEVER overrides deterministic rule results.
  ai: AiSignals = {};

  // ── Score accumulators (computed by RuleEngine after all rules run) ───────
  spamScore:     number = 0;
  phishingScore: number = 0;

  // ─── Constructor ──────────────────────────────────────────────────────────
  constructor(
    parsedEmail: ParsedEmail,
    authResult:  AuthResult,
    reputation:  ReputationSignals,
    behavior:    BehaviorSignals,
    malware:     MalwareSignals | null = null,
  ) {
    this.parsedEmail = parsedEmail;
    this.authResult  = authResult;
    this.reputation  = reputation;
    this.behavior    = behavior;
    this.malware     = malware;
  }

  // ─── Convenience helpers ──────────────────────────────────────────────────

  /** Register a rule result. Rules call this instead of directly mutating state. */
  addResult(result: RuleResult): void {
    this.ruleResults.set(result.ruleId, result);
  }

  /** Check if a specific rule was triggered (for rule dependency checks). */
  isTriggered(ruleId: string): boolean {
    return this.ruleResults.get(ruleId)?.triggered ?? false;
  }

  /** Get score contribution of a triggered rule (0 if not triggered). */
  getRuleScore(ruleId: string): number {
    const r = this.ruleResults.get(ruleId);
    return r?.triggered ? r.score : 0;
  }

  /** All triggered rules as an array. */
  getTriggeredRules(): RuleResult[] {
    return [...this.ruleResults.values()].filter(r => r.triggered);
  }

  /** All triggered rule IDs (for compatibility with existing classification format). */
  getTriggeredRuleIds(): string[] {
    return this.getTriggeredRules().map(r => r.ruleId);
  }

  /** Triggered rules in a specific category. */
  getTriggeredByCategory(category: RuleCategory): RuleResult[] {
    return this.getTriggeredRules().filter(r => r.category === category);
  }
}

// ─── Default / empty signals (used when external services are unavailable) ───
export const UNKNOWN_REPUTATION: ReputationSignals = {
  senderIpReputation:           'unknown',
  domainReputation:             'unknown',
  urlReputation:                'unknown',
  attachmentHashReputation:     'unknown',
  overallThreatScore:           0,
  details:                      'Reputation check unavailable',
};

export const DEFAULT_BEHAVIOR: BehaviorSignals = {
  previousEmailCount: 0,
  typicalTopic:       'unknown',
  behaviorScore:      0,
  anomalyFlag:        false,
  anomalyDescription: '',
};
