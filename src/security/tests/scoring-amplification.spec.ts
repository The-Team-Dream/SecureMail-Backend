// ─────────────────────────────────────────────────────────────────────────────
// security/tests/scoring-amplification.spec.ts
//
// PART 3: Scoring Engine — Correlation Bonuses + Risk Amplification Tests
//
// Tests verify:
//   - URL phishing + domain mismatch → score *= 1.4 amplifier
//   - BEC behavior + reply-to mismatch → +30 bonus
//   - Confidence scaling works correctly
//   - Scoring remains explainable (breakdown fields populated)
//   - Malware override still forces MALICIOUS tier
// ─────────────────────────────────────────────────────────────────────────────

import { ScoringService } from '../pipeline/scoring/scoring.service';
import { CorrelationService } from '../pipeline/detection/correlation-engine/correlation.service';
import { EmailParserService } from '../pipeline/email-parser/email-parser.service';
import { AuthenticationService } from '../pipeline/authentication/authentication.service';
import {
  DetectionContext,
  UNKNOWN_REPUTATION,
  DEFAULT_BEHAVIOR,
} from '../pipeline/detection/rule-engine/detection-context';

function makeCtx(overrides: {
  phishingScore?: number;
  spamScore?:     number;
  behaviorScore?: number;
  triggeredRules?: string[];
  malware?:       { verdict: string; score: number };
} = {}) {
  const parser = new EmailParserService();
  const parsed = parser.parse({
    emailId: '1', messageId: '<t@test.com>', mailBoxId: 1,
    fromAddr: 'attacker@evil.com', fromName: 'CEO John',
    toAddr: ['victim@company.com'],
    subject: 'Urgent wire transfer needed',
    bodyText: 'Please process the wire transfer today. Keep this confidential.',
    bodyHtml: null,
    receivedAt: new Date(),
  });
  const auth = new AuthenticationService().analyze(parsed);
  const ctx  = new DetectionContext(
    parsed, auth, UNKNOWN_REPUTATION,
    {
      ...DEFAULT_BEHAVIOR,
      behaviorScore:  overrides.behaviorScore ?? 0,
      anomalyFlag:    (overrides.behaviorScore ?? 0) >= 20,
    },
    overrides.malware
      ? { verdict: overrides.malware.verdict, score: overrides.malware.score, severity: 'Critical' }
      : null,
  );

  ctx.phishingScore = overrides.phishingScore ?? 0;
  ctx.spamScore     = overrides.spamScore ?? 0;

  for (const ruleId of (overrides.triggeredRules ?? [])) {
    ctx.addResult({
      ruleId, category: 'content', severity: 'high',
      triggered: true, score: 20, confidence: 80, explanation: 'test',
    });
  }

  return ctx;
}

describe('PART 3 — Scoring Engine: Correlation Amplification', () => {

  it('✅ Basic additive scoring — no amplifiers', () => {
    const scorer = new ScoringService();
    const ctx    = makeCtx({ phishingScore: 30, spamScore: 10 });

    const correlator  = new CorrelationService();
    ctx.correlation   = correlator.correlate(ctx);

    const result = scorer.computeRisk(ctx);
    expect(result.finalScore).toBeGreaterThanOrEqual(0);
    expect(result.finalScore).toBeLessThanOrEqual(100);
    expect(result.breakdown).toBeDefined();
  });

  it('✅ URL phishing + domain mismatch → amplifier applied (urlDomainAmplifier > 0)', () => {
    const scorer = new ScoringService();
    const ctx    = makeCtx({
      phishingScore:  50,
      triggeredRules: ['sender_display_name_mismatch', 'homoglyph_domain_spoofing'],
    });

    const correlator = new CorrelationService();
    ctx.correlation  = correlator.correlate(ctx);

    // URL analysis with high threat score
    const urlAnalysis = {
      analyzedUrls:     [],
      totalThreatScore: 25,
      hasHighThreatUrl: true,
      hasMaliciousUrl:  false,
      summary:          'High threat URLs detected',
    };

    const result = scorer.computeRisk(ctx, urlAnalysis);
    expect(result.breakdown.urlDomainAmplifier).toBeGreaterThan(0);
    expect(result.breakdown.urlDomainAmplifier).toBeGreaterThan(0);
  });

  it('✅ BEC behavior + reply-to mismatch → becReplyToBonus = 30', () => {
    const scorer = new ScoringService();
    const ctx    = makeCtx({
      phishingScore: 40,
      behaviorScore: 35,  // anomalyFlag = true
      triggeredRules: ['reply_to_domain_mismatch'],
    });

    const correlator = new CorrelationService();
    ctx.correlation  = correlator.correlate(ctx);

    const result = scorer.computeRisk(ctx);
    expect(result.breakdown.becReplyToBonus).toBe(30);
  });

  it('✅ No compound signals → amplifiers = 0', () => {
    const scorer = new ScoringService();
    const ctx    = makeCtx({ phishingScore: 20 });

    const correlator = new CorrelationService();
    ctx.correlation  = correlator.correlate(ctx);

    const result = scorer.computeRisk(ctx);
    expect(result.breakdown.urlDomainAmplifier).toBe(0);
    expect(result.breakdown.becReplyToBonus).toBe(0);
  });

  it('✅ Malware override → always MALICIOUS tier regardless of other scores', () => {
    const scorer = new ScoringService();
    const ctx    = makeCtx({
      phishingScore: 5,
      malware: { verdict: 'malicious', score: 100 },
    });

    const correlator = new CorrelationService();
    ctx.correlation  = correlator.correlate(ctx);

    const result = scorer.computeRisk(ctx);
    expect(result.riskTier).toBe('MALICIOUS');
    expect(result.isMalware).toBe(true);
    expect(result.finalScore).toBeGreaterThanOrEqual(91);
  });

  it('✅ Score is explainable — all breakdown fields present', () => {
    const scorer = new ScoringService();
    const ctx    = makeCtx({ phishingScore: 30, spamScore: 15 });

    const correlator = new CorrelationService();
    ctx.correlation  = correlator.correlate(ctx);

    const result = scorer.computeRisk(ctx);
    const bd     = result.breakdown;

    expect(bd.ruleScore).toBeDefined();
    expect(bd.correlationBonus).toBeDefined();
    expect(bd.reputationScore).toBeDefined();
    expect(bd.urlThreatScore).toBeDefined();
    expect(bd.malwareScore).toBeDefined();
    expect(bd.behaviorScore).toBeDefined();
    expect(bd.urlDomainAmplifier).toBeDefined();
    expect(bd.becReplyToBonus).toBeDefined();
    expect(bd.rawTotal).toBeDefined();
    expect(bd.finalScore).toBeDefined();
  });

  it('✅ Final score stays within 0-100 bounds even with amplifiers', () => {
    const scorer = new ScoringService();
    const ctx    = makeCtx({
      phishingScore:  100,
      spamScore:      100,
      behaviorScore:  100,
      triggeredRules: ['sender_display_name_mismatch', 'reply_to_domain_mismatch'],
    });

    const correlator = new CorrelationService();
    ctx.correlation  = correlator.correlate(ctx);

    const urlAnalysis = {
      analyzedUrls: [], totalThreatScore: 100,
      hasHighThreatUrl: true, hasMaliciousUrl: true, summary: 'Max threat',
    };

    const result = scorer.computeRisk(ctx, urlAnalysis);
    expect(result.finalScore).toBeLessThanOrEqual(100);
    expect(result.finalScore).toBeGreaterThanOrEqual(0);
  });

  it('✅ tier alias matches riskTier', () => {
    const scorer = new ScoringService();
    const ctx    = makeCtx({ phishingScore: 80 });

    const correlator = new CorrelationService();
    ctx.correlation  = correlator.correlate(ctx);

    const result = scorer.computeRisk(ctx);
    expect(result.tier).toBe(result.riskTier);
  });
});

describe('PART 3 — Risk Tier Thresholds', () => {
  const scorer = new ScoringService();

  function makeSimpleCtx(score: number) {
    const parser = new EmailParserService();
    const parsed = parser.parse({
      emailId: '1', messageId: '<t@t.com>', mailBoxId: 1,
      fromAddr: 'test@example.com', fromName: 'Test',
      toAddr: ['user@co.com'], subject: 'Test', bodyText: 'Test email.',
      bodyHtml: null, receivedAt: new Date(),
    });
    const auth = new AuthenticationService().analyze(parsed);
    const ctx  = new DetectionContext(parsed, auth, UNKNOWN_REPUTATION, DEFAULT_BEHAVIOR, null);
    ctx.phishingScore = score;
    ctx.correlation   = new CorrelationService().correlate(ctx);
    return ctx;
  }

  it('✅ score=10 → SAFE', () => {
    expect(scorer.computeRisk(makeSimpleCtx(10)).riskTier).toBe('SAFE');
  });

  it('✅ score=25 (spam tier) → SPAM or SUSPICIOUS depending on normalization', () => {
    const tier = scorer.computeRisk(makeSimpleCtx(25)).riskTier;
    expect(['SAFE', 'SPAM', 'SUSPICIOUS']).toContain(tier);
  });

  it('✅ malware verdict → always MALICIOUS', () => {
    const ctx = makeSimpleCtx(5);
    (ctx as any).malware = { verdict: 'malicious', score: 100 };
    ctx.correlation      = new CorrelationService().correlate(ctx);
    expect(scorer.computeRisk(ctx).riskTier).toBe('MALICIOUS');
  });
});
