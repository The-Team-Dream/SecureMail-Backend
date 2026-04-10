// ─────────────────────────────────────────────────────────────────────────────
// security/tests/scoring-amplification.spec.ts
// ─────────────────────────────────────────────────────────────────────────────

import { ScoringService }      from '../pipeline/8-scoring/scoring.service';
import { CorrelationService }  from '../pipeline/7-detection/correlation-engine/correlation.service';
import { EmailParserService }  from '../pipeline/1-email-parser/email-parser.service';
import { AuthenticationService } from '../pipeline/2-authentication/authentication.service';
import { DetectionContext }    from '../pipeline/7-detection/rule-engine/detection-context';
import { UNKNOWN_REPUTATION, DEFAULT_BEHAVIOR } from '../constants/default-signals.constant';

// ─── Helpers ──────────────────────────────────────────────────────────────────

/**
 * بدل ctx.phishingScore = X — بنضيف rule بالـ scoreTarget والـ amplifiedScore المناسب.
 * الـ ScoringService بيلف على ruleResults ويحسب phishing/spam scores منهم.
 */
function addPhishingScore(ctx: DetectionContext, score: number, id = 'test_phishing'): void {
  ctx.addResult({
    ruleId:        id,
    category:      'content',
    severity:      3,
    triggered:     true,
    originalScore:  score,
    amplifiedScore: score,
    scoreTarget:   'phishing',
    confidence:    80,
    explanation:   `test phishing score: ${score}`,
  });
}

function addSpamScore(ctx: DetectionContext, score: number, id = 'test_spam'): void {
  ctx.addResult({
    ruleId:        id,
    category:      'content',
    severity:      2,
    triggered:     true,
    originalScore:  score,
    amplifiedScore: score,
    scoreTarget:   'spam',
    confidence:    80,
    explanation:   `test spam score: ${score}`,
  });
}

function addTriggeredRule(ctx: DetectionContext, ruleId: string, score = 20): void {
  ctx.addResult({
    ruleId,
    category:      'content',
    severity:      3,
    triggered:     true,
    originalScore:  score,
    amplifiedScore: score,
    scoreTarget:   'phishing',
    confidence:    80,
    explanation:   'test rule',
  });
}

// ─── Factory ──────────────────────────────────────────────────────────────────

function makeCtx(overrides: {
  phishingScore?:  number;
  spamScore?:      number;
  behaviorScore?:  number;
  triggeredRules?: string[];
  malware?:        { verdict: string; score: number };
  urlResult?:      any;
} = {}) {
  const parser = new EmailParserService();
  const parsed = parser.parse({
    emailId: '1', messageId: '<t@test.com>', mailBoxId: 1,
    fromAddr: 'attacker@evil.com', fromName: 'CEO John',
    toAddr:  ['victim@company.com'],
    subject: 'Urgent wire transfer needed',
    bodyText: 'Please process the wire transfer today. Keep this confidential.',
    bodyHtml: null, receivedAt: new Date(),
  });

  const auth = new AuthenticationService().analyze(parsed);
  const ctx  = new DetectionContext(
    parsed, auth, UNKNOWN_REPUTATION,
    {
      ...DEFAULT_BEHAVIOR,
      behaviorScore: overrides.behaviorScore ?? 0,
      anomalyFlag:   (overrides.behaviorScore ?? 0) >= 20,
    },
    overrides.urlResult ?? null,
    overrides.malware
      ? { verdict: overrides.malware.verdict, score: overrides.malware.score, severity: 'Critical' }
      : null,
  );

  // بدل ctx.phishingScore/spamScore — بنضيف rules بالـ scoreTarget
  if (overrides.phishingScore) addPhishingScore(ctx, overrides.phishingScore);
  if (overrides.spamScore)     addSpamScore(ctx, overrides.spamScore);

  for (const ruleId of (overrides.triggeredRules ?? [])) {
    addTriggeredRule(ctx, ruleId);
  }

  return ctx;
}

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('Scoring Engine — Correlation Amplification', () => {

  it('✅ Basic additive scoring — no amplifiers', async () => {
    const scorer = new ScoringService();
    const ctx    = makeCtx({ phishingScore: 30, spamScore: 10 });
    ctx.setCorrelation(await new CorrelationService().correlate(ctx));

    const result = scorer.computeRisk(ctx);
    expect(result.finalScore).toBeGreaterThanOrEqual(0);
    expect(result.finalScore).toBeLessThanOrEqual(100);
    expect(result.breakdown).toBeDefined();
  });

  it('✅ URL phishing + domain mismatch → urlDomainAmplifier > 0', async () => {
    const scorer = new ScoringService();
    const ctx    = makeCtx({
      phishingScore:  50,
      triggeredRules: ['sender_display_name_mismatch', 'homoglyph_domain_spoofing'],
      urlResult: {
        analyzedUrls:     [],
        totalThreatScore: 25,
        hasHighThreatUrl: true,
        hasMaliciousUrl:  false,
        summary:          'High threat URLs',
      },
    });
    ctx.setCorrelation(await new CorrelationService().correlate(ctx));

    const result = scorer.computeRisk(ctx);
    expect(result.breakdown.urlDomainAmplifier).toBeGreaterThan(0);
  });

  it('✅ BEC behavior + reply-to mismatch → becReplyToBonus = 30', async () => {
    const scorer = new ScoringService();
    const ctx    = makeCtx({
      phishingScore:  40,
      behaviorScore:  35,
      triggeredRules: ['reply_to_domain_mismatch'],
    });
    ctx.setCorrelation(await new CorrelationService().correlate(ctx));

    const result = scorer.computeRisk(ctx);
    expect(result.breakdown.becReplyToBonus).toBe(30);
  });

  it('✅ No compound signals → amplifiers = 0', async () => {
    const scorer = new ScoringService();
    const ctx    = makeCtx({ phishingScore: 20 });
    ctx.setCorrelation(await new CorrelationService().correlate(ctx));

    const result = scorer.computeRisk(ctx);
    expect(result.breakdown.urlDomainAmplifier).toBe(0);
    expect(result.breakdown.becReplyToBonus).toBe(0);
  });

  it('✅ Malware override → always MALICIOUS tier', async () => {
    const scorer = new ScoringService();
    const ctx    = makeCtx({
      phishingScore: 5,
      malware: { verdict: 'malicious', score: 100 },
    });
    ctx.setCorrelation(await new CorrelationService().correlate(ctx));

    const result = scorer.computeRisk(ctx);
    expect(result.riskTier).toBe('MALICIOUS');
    expect(result.isMalware).toBe(true);
    expect(result.finalScore).toBeGreaterThanOrEqual(91);
  });

  it('✅ All breakdown fields present', async () => {
    const scorer = new ScoringService();
    const ctx    = makeCtx({ phishingScore: 30, spamScore: 15 });
    ctx.setCorrelation(await new CorrelationService().correlate(ctx));

    const bd = scorer.computeRisk(ctx).breakdown;
    expect(bd.ruleScore).toBeDefined();
    expect(bd.correlationBonus).toBeDefined();
    expect(bd.reputationScore).toBeDefined();
    expect(bd.authPenalty).toBeDefined();
    expect(bd.urlThreatScore).toBeDefined();
    expect(bd.malwareScore).toBeDefined();
    expect(bd.behaviorScore).toBeDefined();
    expect(bd.urlDomainAmplifier).toBeDefined();
    expect(bd.becReplyToBonus).toBeDefined();
    expect(bd.rawTotal).toBeDefined();
    expect(bd.finalScore).toBeDefined();
  });

  it('✅ Final score stays within 0-100 even with max amplifiers', async () => {
    const scorer = new ScoringService();
    const ctx    = makeCtx({
      phishingScore:  100,
      spamScore:      100,
      behaviorScore:  100,
      triggeredRules: ['sender_display_name_mismatch', 'reply_to_domain_mismatch'],
      urlResult: {
        analyzedUrls:     [],
        totalThreatScore: 100,
        hasHighThreatUrl: true,
        hasMaliciousUrl:  true,
        summary:          'Max threat',
      },
    });
    ctx.setCorrelation(await new CorrelationService().correlate(ctx));

    const result = scorer.computeRisk(ctx);
    expect(result.finalScore).toBeLessThanOrEqual(100);
    expect(result.finalScore).toBeGreaterThanOrEqual(0);
  });

  it('✅ tier alias matches riskTier', async () => {
    const scorer = new ScoringService();
    const ctx    = makeCtx({ phishingScore: 80 });
    ctx.setCorrelation(await new CorrelationService().correlate(ctx));

    const result = scorer.computeRisk(ctx);
    expect(result.tier).toBe(result.riskTier);
  });

  it('✅ ruleScore computed from ruleResults (not ctx.phishingScore)', async () => {
    const scorer = new ScoringService();
    const ctx    = makeCtx();

    // ضيف rule بـ scoreTarget=phishing وـ amplifiedScore=60
    addPhishingScore(ctx, 60, 'phishing_rule_1');
    addSpamScore(ctx, 20, 'spam_rule_1');
    ctx.setCorrelation(await new CorrelationService().correlate(ctx));

    const result = scorer.computeRisk(ctx);
    // الـ ruleScore لازم > 0 لأن في triggered rules
    expect(result.breakdown.ruleScore).toBeGreaterThan(0);
  });
});

// ─── Risk Tier Thresholds ─────────────────────────────────────────────────────

describe('Risk Tier Thresholds', () => {
  const scorer = new ScoringService();

  async function makeSimpleCtx(phishingScore: number) {
    const parser = new EmailParserService();
    const parsed = parser.parse({
      emailId: '1', messageId: '<t@t.com>', mailBoxId: 1,
      fromAddr: 'test@example.com', fromName: 'Test',
      toAddr: ['user@co.com'], subject: 'Test',
      bodyText: 'Test email.', bodyHtml: null, receivedAt: new Date(),
    });
    const auth = new AuthenticationService().analyze(parsed);
    const ctx  = new DetectionContext(parsed, auth, UNKNOWN_REPUTATION, DEFAULT_BEHAVIOR, null, null);

    // بدل ctx.phishingScore = X — بنضيف rule
    if (phishingScore > 0) addPhishingScore(ctx, phishingScore);
    ctx.setCorrelation(await new CorrelationService().correlate(ctx));
    return ctx;
  }

  it('✅ score=0 → SAFE', async () => {
    expect(scorer.computeRisk(await makeSimpleCtx(0)).riskTier).toBe('SAFE');
  });

  it('✅ score=25 → SAFE/SPAM/SUSPICIOUS', async () => {
    const tier = scorer.computeRisk(await makeSimpleCtx(25)).riskTier;
    expect(['SAFE', 'SPAM', 'SUSPICIOUS']).toContain(tier);
  });

  it('✅ malware verdict → always MALICIOUS', async () => {
    const ctx = await makeSimpleCtx(5);
    ctx.setMalware({ verdict: 'malicious', score: 100, severity: 'Critical' });
    ctx.setCorrelation(await new CorrelationService().correlate(ctx));
    expect(scorer.computeRisk(ctx).riskTier).toBe('MALICIOUS');
  });
});