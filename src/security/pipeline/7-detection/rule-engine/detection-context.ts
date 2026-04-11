import {
  AiIntegrationMeta,
  AiSignals,
  AuthSignals,
  CorrelationResult,
  FinalVerdict,
  MalwareIntegrationMeta,
  MalwareSignals,
  ParsedEmail,
  ReputationSignals,
  RiskAssessment,
  RuleCategory,
  RuleResult,
  UrlAnalysisSignals,
} from 'src/security/types';
import { BehaviorSignals } from 'src/security/types/behavior.types';

export class DetectionContext {
  parsedEmail: ParsedEmail;
  authResult: AuthSignals;
  reputation: ReputationSignals;
  behavior: BehaviorSignals;
  urlResult: UrlAnalysisSignals | null = null;
  malware: MalwareSignals | null = null;
  malwareIntegration: MalwareIntegrationMeta = { state: 'skipped', atMs: 0 };
  // ── Stage 8-9: Rule Engine results ───────────────────────────────────────
  ruleResults: Map<string, RuleResult> = new Map();
  // ── Stage 10: Correlation ─────────────────────────────────────────────────
  correlation: CorrelationResult = {
    patterns: [],
    bonusScore: 0,
    description: '',
  };
  // ── Stage 11: Risk Assessment (set by ScoringService) ────────────────────
  riskAssessment: RiskAssessment | null = null;
  // ── Stage 12: Final Verdict (set by DecisionService) ─────────────────────
  verdict: FinalVerdict | null = null;
  // ── Stage 13: AI Report (set by AiAgentService) ───────────────────────────
  ai: AiSignals = {};
  aiIntegration: AiIntegrationMeta = { state: 'skipped', atMs: 0 };

  constructor(
    parsedEmail: ParsedEmail,
    authResult: AuthSignals,
    reputation: ReputationSignals,
    behavior: BehaviorSignals,
    urlResult: UrlAnalysisSignals | null = null,
    malware: MalwareSignals | null = null,
    malwareIntegration: MalwareIntegrationMeta | null = null,
  ) {
    this.parsedEmail = parsedEmail;
    this.authResult = authResult;
    this.reputation = reputation;
    this.behavior = behavior;
    this.urlResult = urlResult;
    this.malware = malware;
    this.malwareIntegration = malwareIntegration ?? { state: 'skipped', atMs: Date.now() };
  }

  setCorrelation(result: CorrelationResult | null | undefined): void {
    this.correlation = result ?? { patterns: [], bonusScore: 0, description: '' };
  }
  setRiskAssessment(result: RiskAssessment | null | undefined): void {
    this.riskAssessment = result ?? null;
  }

  setVerdict(result: FinalVerdict | null | undefined): void {
    this.verdict = result ?? null;
  }

  setAiReport(result: AiSignals | null | undefined): void {
    this.ai = result ?? {};
  }

  setAiIntegration(meta: AiIntegrationMeta | null | undefined): void {
    this.aiIntegration = meta ?? { state: 'skipped', atMs: Date.now() };
  }
  setMalware(result: MalwareSignals | null | undefined): void {
    this.malware = result ?? null;
  }

  setMalwareIntegration(meta: MalwareIntegrationMeta | null | undefined): void {
    this.malwareIntegration = meta ?? { state: 'skipped', atMs: Date.now() };
  }


  // ─── Convenience helpers ──────────────────────────────────────────────────
  hasMaliciousUrl(): boolean {
    return this.urlResult?.hasMaliciousUrl ?? false;
  }

  hasMalware(): boolean {
    return this.malware?.verdict === 'malicious';
  }

  // addSpamScore(score: number): void {
  //   this.spamScore = Math.min(100, this.spamScore + score);
  // }

  // addPhishingScore(score: number): void {
  //   this.phishingScore = Math.min(100, this.phishingScore + score);
  // }

  // ─── Rule Engine helpers ──────────────────────────────────────────────────
  addResult(result: RuleResult): void {
    this.ruleResults.set(result.ruleId, result);
  }

  isTriggered(ruleId: string): boolean {
    return this.ruleResults.get(ruleId)?.triggered ?? false;
  }

  getRuleScore(ruleId: string): number {
    const r = this.ruleResults.get(ruleId);
    return r?.triggered ? r.originalScore : 0;
  }

  getTriggeredRules(): RuleResult[] {
    return [...this.ruleResults.values()].filter(r => r.triggered);
  }

  getTriggeredRuleIds(): string[] {
    return this.getTriggeredRules().map(r => r.ruleId);
  }

  getTriggeredByCategory(category: RuleCategory): RuleResult[] {
    return this.getTriggeredRules().filter(r => r.category === category);
  }
}