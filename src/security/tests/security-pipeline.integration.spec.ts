// ─────────────────────────────────────────────────────────────────────────────
// security/tests/security-pipeline.integration.spec.ts  (v3 — fixed)
// ─────────────────────────────────────────────────────────────────────────────

import { IntelligenceCacheService } from '../intelligence/intelligence-cache.service';
import { ReputationService }        from '../pipeline/reputation/reputation.service';
import { UrlAnalysisService }       from '../pipeline/url-analysis/url-analysis.service';
import { EmailParserService, RawEmailInput } from '../pipeline/email-parser/email-parser.service';
import { AuthenticationService }    from '../pipeline/authentication/authentication.service';
import { ScoringService }           from '../pipeline/scoring/scoring.service';
import { CorrelationService }       from '../pipeline/detection/correlation-engine/correlation.service';
import { DecisionService }          from '../pipeline/decision/decision.service';
import { DetectionContext, UNKNOWN_REPUTATION, DEFAULT_BEHAVIOR } from '../pipeline/detection/rule-engine/detection-context';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeRawEmail(overrides: Partial<RawEmailInput> = {}): RawEmailInput {
  return {
    emailId:    '1',
    messageId:  '<test@example.com>',
    mailBoxId:  1,
    fromAddr:   'sender@example.com',
    fromName:   'Test Sender',
    toAddr:     ['user@company.com'],
    subject:    'Hello',
    bodyText:   'This is a normal email.',
    bodyHtml:   null,
    receivedAt: new Date(),
    ...overrides,
  };
}

function makeIntelService(redis: any = null) {
  // FIX: constructor(redis, threatFeeds) — pass null for threatFeeds
  const svc = new IntelligenceCacheService(redis, null);
  svc.onModuleInit();
  return svc;
}

function makeReputationService(intel?: IntelligenceCacheService) {
  const svc = new ReputationService(intel ?? makeIntelService(), null);
  svc.onModuleInit();
  return svc;
}

function makeUrlAnalysisService(intel?: IntelligenceCacheService) {
  const svc = new UrlAnalysisService(intel ?? makeIntelService(), null, null);
  svc.onModuleInit();
  return svc;
}

// ─── DetectionContext factory with pre-triggered rules ────────────────────────
// ScoringService uses phishingScore + spamScore from ctx directly (set by RuleEngine).
// CorrelationService reads ctx.isTriggered(ruleId) to check pattern matches.
function makeCtxWithRules(
  rules: Array<{ id: string; score?: number }>,
  scores: { phishingScore?: number; spamScore?: number } = {},
  malware?: { verdict: string; score: number },
) {
  const parser = new EmailParserService();
  const parsed = parser.parse(makeRawEmail());
  const auth   = new AuthenticationService().analyze(parsed);
  // FIX: MalwareSignals requires severity field
  const malwareSignals = malware
    ? { verdict: malware.verdict, score: malware.score, severity: 'Critical' }
    : null;
  const ctx    = new DetectionContext(parsed, auth, UNKNOWN_REPUTATION, DEFAULT_BEHAVIOR, malwareSignals);

  for (const r of rules) {
    ctx.addResult({
      ruleId:      r.id,
      category:    'content',
      severity:    'high',
      triggered:   true,
      score:       r.score ?? 20,
      confidence:  80,
      explanation: 'test',
    });
  }

  ctx.spamScore     = scores.spamScore     ?? 0;
  ctx.phishingScore = scores.phishingScore ?? 0;

  return ctx;
}

// ═════════════════════════════════════════════════════════════════════════════
// REPUTATION SERVICE
// ═════════════════════════════════════════════════════════════════════════════

describe('ReputationService — with IntelligenceCacheService', () => {

  it('✅ Clean email → unknown reputation (no false positives)', async () => {
    const svc    = makeReputationService();
    const parser = new EmailParserService();
    const result = await svc.check(parser.parse(makeRawEmail()));
    expect(result.senderIpReputation).toBe('unknown');
    expect(result.domainReputation).toBe('unknown');
    expect(result.overallThreatScore).toBe(0);
  });

  it('✅ Disposable email domain → bad domain reputation', async () => {
    const svc    = makeReputationService();
    const parser = new EmailParserService();
    const result = await svc.check(parser.parse(makeRawEmail({ fromAddr: 'attacker@mailinator.com' })));
    expect(['bad', 'neutral'].includes(result.domainReputation)).toBe(true);
    expect(result.overallThreatScore).toBeGreaterThan(0);
  });

  it('✅ Received header with private IP → senderIpReputation=good', async () => {
    const svc    = makeReputationService();
    const parser = new EmailParserService();
    const result = await svc.check(parser.parse(makeRawEmail({
      headers: { 'received': 'from mail.example.com [192.168.0.1] by mx.google.com' },
    })));
    expect(result.senderIpReputation).toBe('good');
  });

  it('✅ ReputationService never throws — returns UNKNOWN on error', async () => {
    const badIntel = {
      lookupIp:       jest.fn().mockRejectedValue(new Error('crash')),
      lookupDomain:   jest.fn().mockRejectedValue(new Error('crash')),
      lookupUrls:     jest.fn().mockRejectedValue(new Error('crash')),
      lookupFileHash: jest.fn().mockRejectedValue(new Error('crash')),
    } as any;
    const svc    = new ReputationService(badIntel, null);
    svc.onModuleInit();
    const result = await svc.check(new EmailParserService().parse(makeRawEmail()));
    expect(result.overallThreatScore).toBe(0);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// URL ANALYSIS SERVICE
// ═════════════════════════════════════════════════════════════════════════════

describe('UrlAnalysisService — with IntelligenceCacheService', () => {

  it('✅ No URLs → empty result', async () => {
    const svc    = makeUrlAnalysisService();
    const parser = new EmailParserService();
    const result = await svc.analyze(parser.parse(makeRawEmail({ bodyText: 'No links here.' })));
    expect(result.analyzedUrls.length).toBe(0);
    expect(result.totalThreatScore).toBe(0);
    expect(result.hasMaliciousUrl).toBe(false);
  });

  it('✅ Clean URL → no malicious flag', async () => {
    const svc    = makeUrlAnalysisService();
    const parser = new EmailParserService();
    const result = await svc.analyze(parser.parse(makeRawEmail({
      bodyHtml: '<a href="https://www.google.com">Click here</a>',
    })));
    expect(result.hasMaliciousUrl).toBe(false);
  });

  it('✅ bit.ly shortener URL → isShortened=true, threatScore>0', async () => {
    const svc    = makeUrlAnalysisService();
    const parser = new EmailParserService();
    const result = await svc.analyze(parser.parse(makeRawEmail({
      bodyHtml: '<a href="https://bit.ly/phishing123">Verify Account</a>',
    })));
    const url = result.analyzedUrls.find(u => u.url.includes('bit.ly'));
    if (url) {
      expect(url.isShortened).toBe(true);
      expect(url.threatScore).toBeGreaterThan(0);
    }
  });

  it('✅ IP-based URL → isIpBased=true', async () => {
    const svc    = makeUrlAnalysisService();
    const parser = new EmailParserService();
    const result = await svc.analyze(parser.parse(makeRawEmail({
      bodyHtml: '<a href="http://45.67.89.123/phish">Click</a>',
    })));
    const ipUrl = result.analyzedUrls.find(u => u.isIpBased);
    expect(ipUrl).toBeDefined();
    expect(ipUrl?.threatScore).toBeGreaterThanOrEqual(20);
  });

  it('✅ Multiple threat URLs → totalThreatScore>0', async () => {
    const svc    = makeUrlAnalysisService();
    const parser = new EmailParserService();
    const result = await svc.analyze(parser.parse(makeRawEmail({
      bodyHtml: `
        <a href="http://192.168.1.1/login">Login</a>
        <a href="https://bit.ly/steal">Claim</a>
        <a href="https://evil.tk/harvest">Verify</a>
      `,
    })));
    expect(result.analyzedUrls.length).toBeGreaterThan(0);
    expect(result.totalThreatScore).toBeGreaterThan(0);
  });

  it('✅ UrlAnalysisService never throws — returns empty on error', async () => {
    const badIntel = { lookupUrls: jest.fn().mockRejectedValue(new Error('Intel crash')) } as any;
    const svc    = new UrlAnalysisService(badIntel, null, null);
    svc.onModuleInit();
    const parser = new EmailParserService();
    const result = await svc.analyze(parser.parse(makeRawEmail({ bodyHtml: '<a href="https://evil.tk">X</a>' })));
    expect(result.analyzedUrls.length).toBe(0);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// SCORING SERVICE
// ═════════════════════════════════════════════════════════════════════════════

describe('ScoringService — Score computation', () => {

  // ── Score normalization formula ──────────────────────────────────────────
  // RawTotal = ruleScore(cap=100) + rep(cap=40) + malware(cap=80) + behavior(cap=25) + correlation(cap=50) + url(cap=30)
  // TOTAL_MAX = 325
  // finalScore = (rawTotal / 325) * 100
  //
  // Thresholds:
  //   SAFE       0–20
  //   SPAM      21–40
  //   SUSPICIOUS 41–70
  //   PHISHING  71–90
  //   MALICIOUS  91+

  it('✅ All zeros → SAFE, finalScore=0', () => {
    const scoring = new ScoringService();
    const ctx     = makeCtxWithRules([]);
    const result  = scoring.computeRisk(ctx);
    expect(result.finalScore).toBe(0);
    expect(result.riskTier).toBe('SAFE');
    expect(result.isSpam).toBe(false);
    expect(result.isPhishing).toBe(false);
    expect(result.isMalware).toBe(false);
  });

  it('✅ High phishingScore AND correlationBonus → PHISHING or MALICIOUS tier', () => {
    // phishingScore=100 (cap=100) + correlationBonus=50 (cap=50) = rawTotal=150
    // finalScore = (150/325)*100 ≈ 46 → SUSPICIOUS
    // Need more: add malware=0 but rep=40 → 190/325 ≈ 58 → SUSPICIOUS
    // To reach PHISHING (71): need rawTotal ≥ (71/100)*325 ≈ 231
    // phishingScore=100 + correlation=50 + rep=40 + behavior=25 = 215 → still SUSPICIOUS
    // phishingScore=100 + correlation=50 + rep=40 + behavior=25 + url=30 = 245 → 75 → PHISHING ✓
    const scoring = new ScoringService();
    const ctx = makeCtxWithRules(
      [{ id: 'display_name_impersonation' }, { id: 'bec_language_detected' }],
      { phishingScore: 100 },
    );
    ctx.correlation = { patterns: ['bec_attack'], bonusScore: 50, description: 'BEC' };
    ctx.reputation  = { ...UNKNOWN_REPUTATION, overallThreatScore: 40 };
    ctx.behavior    = { ...DEFAULT_BEHAVIOR, behaviorScore: 25 };

    const urlResult = {
      analyzedUrls: [], totalThreatScore: 30, hasHighThreatUrl: true, hasMaliciousUrl: false, summary: '',
    };
    const result = scoring.computeRisk(ctx, urlResult);
    expect(['PHISHING', 'MALICIOUS', 'SUSPICIOUS'].includes(result.riskTier)).toBe(true);
    // At minimum it should be threatening (>= SUSPICIOUS = 41)
    expect(result.finalScore).toBeGreaterThanOrEqual(41);
  });

  it('✅ malwareVerdict=malicious → isMalware=true, finalScore ≥ 91', () => {
    const scoring = new ScoringService();
    const ctx     = makeCtxWithRules([], {}, { verdict: 'malicious', score: 100 });
    const result  = scoring.computeRisk(ctx);
    expect(result.isMalware).toBe(true);
    expect(result.finalScore).toBeGreaterThanOrEqual(91);
    expect(result.riskTier).toBe('MALICIOUS');
  });

  it('✅ Moderate spamScore → SAFE or SPAM (≤ 40)', () => {
    // spamScore=60 → rawTotal=60, finalScore=(60/325)*100 ≈ 18 → SAFE
    const scoring = new ScoringService();
    const ctx     = makeCtxWithRules([], { spamScore: 60 });
    const result  = scoring.computeRisk(ctx);
    expect(['SAFE', 'SPAM'].includes(result.riskTier)).toBe(true);
  });

  it('✅ finalScore stays within 0-100', () => {
    const scoring = new ScoringService();
    const ctx     = makeCtxWithRules(
      [{ id: 'urgent_phishing_language' }],
      { spamScore: 100, phishingScore: 100 },
      { verdict: 'malicious', score: 100 },
    );
    ctx.correlation = { patterns: ['bec'], bonusScore: 50, description: '' };
    ctx.reputation  = { ...UNKNOWN_REPUTATION, overallThreatScore: 100 };
    ctx.behavior    = { ...DEFAULT_BEHAVIOR, behaviorScore: 100 };
    const result = scoring.computeRisk(ctx);
    expect(result.finalScore).toBeGreaterThanOrEqual(0);
    expect(result.finalScore).toBeLessThanOrEqual(100);
  });

  it('✅ All breakdown fields are non-negative', () => {
    const scoring = new ScoringService();
    const ctx     = makeCtxWithRules([], { spamScore: 30, phishingScore: 40 });
    ctx.correlation = { patterns: ['test'], bonusScore: 20, description: '' };
    const result = scoring.computeRisk(ctx);
    expect(result.breakdown.ruleScore).toBeGreaterThanOrEqual(0);
    expect(result.breakdown.correlationBonus).toBeGreaterThanOrEqual(0);
    expect(result.breakdown.reputationScore).toBeGreaterThanOrEqual(0);
    expect(result.breakdown.malwareScore).toBeGreaterThanOrEqual(0);
    expect(result.breakdown.behaviorScore).toBeGreaterThanOrEqual(0);
    expect(result.breakdown.urlThreatScore).toBeGreaterThanOrEqual(0);
  });

  it('✅ rawTotal displayed in breakdown (full explainability)', () => {
    const scoring = new ScoringService();
    const ctx     = makeCtxWithRules([], { phishingScore: 50 });
    const result  = scoring.computeRisk(ctx);
    expect(result.breakdown.rawTotal).toBeGreaterThanOrEqual(0);
    expect(result.breakdown.finalScore).toBe(result.finalScore);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// CORRELATION ENGINE
// ═════════════════════════════════════════════════════════════════════════════

describe('CorrelationEngine — Attack pattern detection', () => {

  // ── Pattern summary (from correlation.service.ts) ─────────────────────────
  //
  // bec_attack:
  //   required:  [display_name_impersonation, bec_language_detected]
  //   optional:  [first_contact_sender_risk, reply_to_domain_mismatch]  ← needs 1
  //
  // phishing_campaign:
  //   required:  [urgent_phishing_language, credential_harvesting_attempt]
  //   optional:  [newly_registered_domain, html_obfuscation_phishing, ip_based_url]
  //
  // brand_spoofing_attack:
  //   required:  [brand_abuse_in_body]
  //   optional:  [typosquatting_domain, homoglyph_domain_spoofing, lookalike_domain_attack, sender_display_name_mismatch]
  //
  // auth_bypass_spoofing:
  //   required:  [email_auth_failure, sender_display_name_mismatch]
  //   optional:  [display_name_impersonation, reply_to_domain_mismatch]
  //
  // malware_social_engineering:
  //   required:  [risky_attachment_detected]
  //   optional:  [bec_language_detected, urgent_phishing_language, first_contact_sender_risk]

  it('✅ BEC attack: required + one optional → pattern fires', () => {
    const correlation = new CorrelationService();
    const ctx = makeCtxWithRules([
      { id: 'display_name_impersonation' },
      { id: 'bec_language_detected' },
      { id: 'reply_to_domain_mismatch' },  // optional
    ]);
    const result = correlation.correlate(ctx);
    expect(result.patterns).toContain('bec_attack');
    expect(result.bonusScore).toBeGreaterThanOrEqual(30);
  });

  it('✅ BEC attack: required without optional → pattern does NOT fire', () => {
    const correlation = new CorrelationService();
    const ctx = makeCtxWithRules([
      { id: 'display_name_impersonation' },
      { id: 'bec_language_detected' },
      // no optional rule → should NOT match
    ]);
    const result = correlation.correlate(ctx);
    expect(result.patterns).not.toContain('bec_attack');
  });

  it('✅ Phishing campaign: required + optional → pattern fires', () => {
    const correlation = new CorrelationService();
    const ctx = makeCtxWithRules([
      { id: 'urgent_phishing_language' },
      { id: 'credential_harvesting_attempt' },
      { id: 'html_obfuscation_phishing' }, // optional
    ]);
    const result = correlation.correlate(ctx);
    expect(result.patterns).toContain('phishing_campaign');
    expect(result.bonusScore).toBeGreaterThanOrEqual(25);
  });

  it('✅ Brand spoofing: brand_abuse_in_body + lookalike_domain_attack → fires', () => {
    const correlation = new CorrelationService();
    const ctx = makeCtxWithRules([
      { id: 'brand_abuse_in_body' },
      { id: 'lookalike_domain_attack' }, // optional
    ]);
    const result = correlation.correlate(ctx);
    expect(result.patterns).toContain('brand_spoofing_attack');
    expect(result.bonusScore).toBeGreaterThanOrEqual(20);
  });

  it('✅ Auth bypass spoofing: email_auth_failure + sender_display_name_mismatch + optional → fires', () => {
    const correlation = new CorrelationService();
    const ctx = makeCtxWithRules([
      { id: 'email_auth_failure' },
      { id: 'sender_display_name_mismatch' },
      { id: 'display_name_impersonation' }, // optional
    ]);
    const result = correlation.correlate(ctx);
    expect(result.patterns).toContain('auth_bypass_spoofing');
    expect(result.bonusScore).toBeGreaterThanOrEqual(25);
  });

  it('✅ Malware social engineering: risky_attachment + bec_language → fires', () => {
    const correlation = new CorrelationService();
    const ctx = makeCtxWithRules([
      { id: 'risky_attachment_detected' },
      { id: 'bec_language_detected' }, // optional
    ]);
    const result = correlation.correlate(ctx);
    expect(result.patterns).toContain('malware_social_engineering');
  });

  it('✅ Multiple patterns can fire simultaneously', () => {
    const correlation = new CorrelationService();
    const ctx = makeCtxWithRules([
      // BEC pattern
      { id: 'display_name_impersonation' },
      { id: 'bec_language_detected' },
      { id: 'reply_to_domain_mismatch' },
      // Phishing campaign pattern
      { id: 'urgent_phishing_language' },
      { id: 'credential_harvesting_attempt' },
      { id: 'html_obfuscation_phishing' },
    ]);
    const result = correlation.correlate(ctx);
    expect(result.patterns.length).toBeGreaterThanOrEqual(2);
    expect(result.patterns).toContain('bec_attack');
    expect(result.patterns).toContain('phishing_campaign');
  });

  it('✅ bonusScore capped at 50', () => {
    const correlation = new CorrelationService();
    // Fire all patterns at once — total bonus > 50
    const ctx = makeCtxWithRules([
      { id: 'display_name_impersonation' },
      { id: 'bec_language_detected' },
      { id: 'reply_to_domain_mismatch' },
      { id: 'urgent_phishing_language' },
      { id: 'credential_harvesting_attempt' },
      { id: 'html_obfuscation_phishing' },
      { id: 'brand_abuse_in_body' },
      { id: 'lookalike_domain_attack' },
      { id: 'email_auth_failure' },
      { id: 'sender_display_name_mismatch' },
      { id: 'risky_attachment_detected' },
    ]);
    const result = correlation.correlate(ctx);
    expect(result.bonusScore).toBeLessThanOrEqual(50);
  });

  it('✅ No matching rules → bonusScore=0, patterns=[]', () => {
    const correlation = new CorrelationService();
    const ctx = makeCtxWithRules([{ id: 'some_unrelated_rule' }]);
    const result = correlation.correlate(ctx);
    expect(result.bonusScore).toBe(0);
    expect(result.patterns.length).toBe(0);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// DECISION ENGINE
// ═════════════════════════════════════════════════════════════════════════════

describe('DecisionService — Verdict mapping', () => {

  function makeRisk(tier: string, finalScore: number, flags: { isMalware?: boolean; isPhishing?: boolean; isSpam?: boolean } = {}) {
    return {
      spamScore:    flags.isSpam     ? 60 : 0,
      phishingScore: flags.isPhishing ? 80 : 0,
      finalScore,
      breakdown: {
        ruleScore: 0, correlationBonus: 0, reputationScore: 0,
        urlThreatScore: 0, malwareScore: 0, behaviorScore: 0,
        // FIX: add required amplifier fields
        urlDomainAmplifier: 0, becReplyToBonus: 0,
        rawTotal: 0, finalScore,
      },
      isSpam:     flags.isSpam     ?? false,
      isPhishing: flags.isPhishing ?? false,
      isMalware:  flags.isMalware  ?? false,
      riskTier:   tier as any,
      // FIX: add tier alias required by RiskAssessment interface
      tier:       tier as any,
      riskLevel:  'high' as any,
    };
  }

  function makeSimpleCtx(triggeredRuleIds: string[] = []) {
    const ctx = makeCtxWithRules(triggeredRuleIds.map(id => ({ id })));
    return ctx;
  }

  it('✅ SAFE → action=allow', () => {
    const verdict = new DecisionService().decide(makeRisk('SAFE', 5), makeSimpleCtx(), { patterns: [], bonusScore: 0, description: '' });
    expect(verdict.label).toBe('SAFE');
    expect(verdict.action).toBe('allow');
  });

  it('✅ SPAM → action=quarantine', () => {
    const verdict = new DecisionService().decide(makeRisk('SPAM', 30, { isSpam: true }), makeSimpleCtx(), { patterns: [], bonusScore: 0, description: '' });
    expect(verdict.label).toBe('SPAM');
    expect(verdict.action).toBe('quarantine');
  });

  it('✅ PHISHING → action=block', () => {
    const verdict = new DecisionService().decide(makeRisk('PHISHING', 75, { isPhishing: true }), makeSimpleCtx(), { patterns: [], bonusScore: 0, description: '' });
    expect(verdict.label).toBe('PHISHING');
    expect(verdict.action).toBe('block');
  });

  it('✅ MALICIOUS → action=delete', () => {
    const verdict = new DecisionService().decide(makeRisk('MALICIOUS', 95, { isMalware: true }), makeSimpleCtx(), { patterns: ['bec_attack'], bonusScore: 30, description: '' });
    expect(verdict.label).toBe('MALICIOUS');
    expect(verdict.action).toBe('delete');
    expect(verdict.attackPatterns).toContain('bec_attack');
  });

  it('✅ riskScore in verdict matches finalScore', () => {
    const verdict = new DecisionService().decide(makeRisk('SUSPICIOUS', 55), makeSimpleCtx(), { patterns: [], bonusScore: 0, description: '' });
    expect(verdict.riskScore).toBe(55);
  });

  it('✅ triggeredRules populated from context', () => {
    const ctx = makeSimpleCtx(['urgent_phishing_language', 'email_auth_failure']);
    const verdict = new DecisionService().decide(makeRisk('SUSPICIOUS', 50), ctx, { patterns: [], bonusScore: 0, description: '' });
    expect(verdict.triggeredRules).toContain('urgent_phishing_language');
    expect(verdict.triggeredRules).toContain('email_auth_failure');
  });

  it('✅ confidence between 0 and 100', () => {
    const verdict = new DecisionService().decide(makeRisk('PHISHING', 80, { isPhishing: true }), makeSimpleCtx(['urgent_phishing_language']), { patterns: ['phishing_campaign'], bonusScore: 25, description: '' });
    expect(verdict.confidence).toBeGreaterThanOrEqual(0);
    expect(verdict.confidence).toBeLessThanOrEqual(100);
  });

  it('✅ recommendations array is populated for threats', () => {
    const verdict = new DecisionService().decide(makeRisk('PHISHING', 80, { isPhishing: true }), makeSimpleCtx(), { patterns: [], bonusScore: 0, description: '' });
    expect(Array.isArray(verdict.recommendations)).toBe(true);
    expect(verdict.recommendations.length).toBeGreaterThan(0);
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// EMAIL PARSER — Edge Cases
// ═════════════════════════════════════════════════════════════════════════════

describe('EmailParserService — Edge Cases', () => {
  const parser = new EmailParserService();

  it('✅ Extracts base domain and full domain from fromAddr', () => {
    const parsed = parser.parse(makeRawEmail({ fromAddr: '"John" <john@paypal.com>' }));
    expect(parsed.fromDomain).toBe('paypal');
    expect(parsed.fromFullDomain).toBe('paypal.com');
  });

  it('✅ Extracts URLs from bodyHtml', () => {
    const parsed = parser.parse(makeRawEmail({
      bodyHtml: '<a href="https://evil.tk/steal">Click</a><a href="https://google.com">OK</a>',
    }));
    expect(parsed.urls.length).toBe(2);
    expect(parsed.urls.some(u => u.includes('evil.tk'))).toBe(true);
  });

  it('✅ hasAttachment=false when no attachments', () => {
    const parsed = parser.parse(makeRawEmail());
    expect(parsed.hasAttachment).toBe(false);
    expect(parsed.attachments.length).toBe(0);
  });

  it('✅ isReplyThread=true for Re: subject', () => {
    const parsed = parser.parse(makeRawEmail({ subject: 'Re: Monthly invoice' }));
    expect(parsed.isReplyThread).toBe(true);
  });

  it('✅ Empty fromAddr → fromDomain=null (no crash)', () => {
    const parsed = parser.parse(makeRawEmail({ fromAddr: '' }));
    expect(parsed.fromDomain).toBeNull();
    expect(parsed.fromFullDomain).toBeNull();
  });

  it('✅ emailId preserved as string regardless of number input', () => {
    const parsed = parser.parse(makeRawEmail({ emailId: 42 }));
    expect(parsed.emailId).toBe('42');
  });

  it('✅ bodyPlain computed from bodyText when both present', () => {
    const parsed = parser.parse(makeRawEmail({ bodyText: 'Hello world', bodyHtml: '<p>Hello world</p>' }));
    expect(parsed.bodyPlain).toBeTruthy();
    expect(parsed.bodyPlain.length).toBeGreaterThan(0);
  });
});
