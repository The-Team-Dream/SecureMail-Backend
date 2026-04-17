// ─────────────────────────────────────────────────────────────────────────────
// security/tests/security-pipeline.integration.spec.ts
// ─────────────────────────────────────────────────────────────────────────────

import { IntelligenceCacheService } from '../intelligence/intelligence-cache.service';
import { ReputationService }        from '../pipeline/3-reputation/reputation.service';
import { UrlAnalysisService }       from '../pipeline/5-url-analysis/url-analysis.service';
import { EmailParserService }       from '../pipeline/1-email-parser/email-parser.service';
import { AuthenticationService }    from '../pipeline/2-authentication/authentication.service';
import { ScoringService }           from '../pipeline/8-scoring/scoring.service';
import { CorrelationService }       from '../pipeline/7-detection/correlation-engine/correlation.service';
import { DecisionService }          from '../pipeline/9-decision/decision.service';
import { DetectionContext }         from '../pipeline/7-detection/rule-engine/detection-context';
import { UNKNOWN_REPUTATION, DEFAULT_BEHAVIOR } from '../constants/default-signals.constant';
import { RawEmailInput }            from '../types/email.types';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeRawEmail(overrides: Partial<RawEmailInput> = {}): RawEmailInput {
  return {
    emailId: '1', messageId: '<test@example.com>', mailBoxId: 1,
    fromAddr: 'sender@example.com', fromName: 'Test Sender',
    toAddr: ['user@company.com'], subject: 'Hello',
    bodyText: 'This is a normal email.', bodyHtml: null,
    receivedAt: new Date(), ...overrides,
  };
}

function makeIntelService(redis: any = null) {
  const svc = new IntelligenceCacheService(redis, null);
  svc.onModuleInit();
  return svc;
}

/**
 * بدل ctx.phishingScore/spamScore — بنضيف rules بالـ scoreTarget المناسب.
 * الـ ScoringService هو اللي بيجمعهم من ruleResults.
 *
 * rules: Array<{ id, score?, scoreTarget? }>
 *   - scoreTarget default = 'phishing'
 */
function makeCtxWithRules(
  rules: Array<{ id: string; score?: number; scoreTarget?: 'phishing' | 'spam' | 'both' }>,
  malware?: { verdict: string; score: number },
) {
  const parser = new EmailParserService();
  const parsed = parser.parse(makeRawEmail());
  const auth   = new AuthenticationService().analyze(parsed);
  const malwareSignals = malware
    ? { verdict: malware.verdict, score: malware.score, severity: 'Critical' }
    : null;
  const ctx = new DetectionContext(parsed, auth, UNKNOWN_REPUTATION, DEFAULT_BEHAVIOR, null, malwareSignals);

  for (const r of rules) {
    ctx.addResult({
      ruleId:        r.id,
      category:      'content',
      severity:      3,
      triggered:     true,
      originalScore:  r.score ?? 20,
      amplifiedScore: r.score ?? 20,
      scoreTarget:   r.scoreTarget ?? 'phishing',
      confidence:    80,
      explanation:   'test',
    });
  }

  return ctx;
}

// ─── Reputation Service ───────────────────────────────────────────────────────

describe('ReputationService', () => {

  it('✅ Clean email → zero threat scores (no false positives)', async () => {
    const svc    = new ReputationService(makeIntelService());
    const parser = new EmailParserService();
    const result = await svc.check(parser.parse(makeRawEmail()));
    expect(result.ipReputationScore).toBe(0);
    expect(result.domainReputationScore).toBe(0);
  });
});

// ─── URL Analysis Service ─────────────────────────────────────────────────────

describe('UrlAnalysisService', () => {

  it('✅ Email without URLs → empty analyzedUrls', async () => {
    const svc    = new UrlAnalysisService(makeIntelService(), null);
    const parser = new EmailParserService();
    const result = await svc.analyze(parser.parse(makeRawEmail({
      bodyHtml: null, bodyText: 'No links here.',
    })));
    expect(result.analyzedUrls?.length).toBe(0);
    expect(result.totalThreatScore).toBe(0);
    expect(result.hasMaliciousUrl).toBe(false);
  });

  it('✅ IP-based URL → isIpBased = true', async () => {
    const svc    = new UrlAnalysisService(makeIntelService(), null);
    const parser = new EmailParserService();
    const result = await svc.analyze(parser.parse(makeRawEmail({
      bodyText: 'Click: http://192.168.1.100/login',
    })));
    const ipUrl = result.analyzedUrls?.find(u => u.isIpBased);
    expect(ipUrl).toBeDefined();
    expect(ipUrl!.threatScore).toBeGreaterThan(0);
  });

  it('✅ Shortened URL → isShortened = true', async () => {
    const svc    = new UrlAnalysisService(makeIntelService(), null);
    const parser = new EmailParserService();
    const result = await svc.analyze(parser.parse(makeRawEmail({
      bodyText: 'Check: https://bit.ly/abc123',
    })));
    expect(result.analyzedUrls?.some(u => u.isShortened)).toBe(true);
  });

  it('✅ Suspicious TLD → isSuspiciousTld = true', async () => {
    const svc    = new UrlAnalysisService(makeIntelService(), null);
    const parser = new EmailParserService();
    const result = await svc.analyze(parser.parse(makeRawEmail({
      bodyText: 'Visit: http://evil-site.tk/login',
    })));
    expect(result.analyzedUrls?.some(u => u.isSuspiciousTld)).toBe(true);
  });

  it('✅ Clean HTTPS URL → low threat score', async () => {
    const svc    = new UrlAnalysisService(makeIntelService(), null);
    const parser = new EmailParserService();
    const result = await svc.analyze(parser.parse(makeRawEmail({
      bodyText: 'Visit: https://www.google.com/search',
    })));
    expect(result.hasMaliciousUrl).toBe(false);
    expect(result.totalThreatScore).toBeLessThan(30);
  });

  it('✅ totalThreatScore = max×0.7 + avg×0.3', async () => {
    const svc    = new UrlAnalysisService(makeIntelService(), null);
    const parser = new EmailParserService();
    const result = await svc.analyze(parser.parse(makeRawEmail({
      bodyText: 'Bad: http://1.2.3.4/steal Good: https://google.com',
    })));
    const signals  = result.analyzedUrls ?? [];
    if (signals.length > 0) {
      const maxScore = Math.max(...signals.map(s => s.threatScore));
      const avgScore = Math.round(signals.reduce((s, u) => s + u.threatScore, 0) / signals.length);
      const expected = Math.min(100, Math.round(maxScore * 0.7 + avgScore * 0.3));
      expect(result.totalThreatScore).toBe(expected);
    }
  });
});

// ─── Correlation Service ──────────────────────────────────────────────────────

describe('CorrelationService', () => {

  it('✅ BEC attack: impersonation + BEC language + reply-to mismatch', async () => {
    const ctx = makeCtxWithRules([
      { id: 'display_name_impersonation' },
      { id: 'bec_language_detected' },
      { id: 'reply_to_domain_mismatch' },
    ]);
    const result = await new CorrelationService().correlate(ctx);
    expect(result.patterns).toContain('bec_attack');
    expect(result.bonusScore).toBeGreaterThan(0);
  });

  it('✅ Phishing campaign: urgent + credential harvesting + obfuscation', async () => {
    const ctx = makeCtxWithRules([
      { id: 'urgent_phishing_language' },
      { id: 'credential_harvesting_attempt' },
      { id: 'html_obfuscation_phishing' },
    ]);
    const result = await new CorrelationService().correlate(ctx);
    expect(result.patterns).toContain('phishing_campaign');
  });

  it('✅ Auth bypass + spoofing', async () => {
    const ctx = makeCtxWithRules([
      { id: 'email_auth_failure' },
      { id: 'sender_display_name_mismatch' },
      { id: 'display_name_impersonation' },
    ]);
    const result = await new CorrelationService().correlate(ctx);
    expect(result.patterns).toContain('auth_bypass_spoofing');
  });

  it('✅ Multiple patterns fire simultaneously', async () => {
    const ctx = makeCtxWithRules([
      { id: 'display_name_impersonation' },
      { id: 'bec_language_detected' },
      { id: 'reply_to_domain_mismatch' },
      { id: 'urgent_phishing_language' },
      { id: 'credential_harvesting_attempt' },
      { id: 'html_obfuscation_phishing' },
    ]);
    const result = await new CorrelationService().correlate(ctx);
    expect(result.patterns.length).toBeGreaterThanOrEqual(2);
    expect(result.patterns).toContain('bec_attack');
    expect(result.patterns).toContain('phishing_campaign');
  });

  it('✅ No matching rules → bonusScore=0, patterns=[]', async () => {
    const ctx    = makeCtxWithRules([{ id: 'unrelated_rule' }]);
    const result = await new CorrelationService().correlate(ctx);
    expect(result.bonusScore).toBe(0);
    expect(result.patterns.length).toBe(0);
  });
});

// ─── Decision Service ─────────────────────────────────────────────────────────

describe('DecisionService — Verdict mapping with confidence gates', () => {

  function makeRisk(tier: string, finalScore: number, confidence: number, flags: {
    isMalware?: boolean; isPhishing?: boolean; isSpam?: boolean;
  } = {}) {
    return {
      spamScore:      flags.isSpam     ? 60 : 0,
      phishingScore:  flags.isPhishing ? 80 : 0,
      finalScore,
      confidence,
      breakdown: {
        ruleScore:          0,
        correlationBonus:   0,
        reputationScore:    0,
        authPenalty:        0,
        urlThreatScore:     0,
        malwareScore:       0,
        behaviorScore:      0,
        urlDomainAmplifier: 0,
        becReplyToBonus:    0,
        rawTotal:           finalScore,
        finalScore,
      },
      isSpam:     flags.isSpam     ?? false,
      isPhishing: flags.isPhishing ?? false,
      isMalware:  flags.isMalware  ?? false,
      riskTier:   tier as any,
      tier:       tier as any,
      riskLevel:  'high' as any,
    };
  }

  it('✅ SAFE → action=allow', () => {
    const v = new DecisionService().decide(makeRisk('SAFE', 5, 40), makeCtxWithRules([]));
    expect(v.label).toBe('SAFE');
    expect(v.action).toBe('allow');
  });

  it('✅ SPAM → action=quarantine', () => {
    const v = new DecisionService().decide(makeRisk('SPAM', 30, 60, { isSpam: true }), makeCtxWithRules([]));
    expect(v.label).toBe('SPAM');
    expect(v.action).toBe('quarantine');
  });

  it('✅ PHISHING + high confidence → action=block', () => {
    const v = new DecisionService().decide(makeRisk('PHISHING', 80, 80, { isPhishing: true }), makeCtxWithRules([]));
    expect(v.label).toBe('PHISHING');
    expect(v.action).toBe('block');
  });

  it('✅ PHISHING + low confidence → action=quarantine', () => {
    const v = new DecisionService().decide(makeRisk('PHISHING', 76, 45, { isPhishing: true }), makeCtxWithRules([]));
    expect(v.label).toBe('PHISHING');
    expect(v.action).toBe('quarantine');
  });

  it('✅ MALICIOUS + malware → action=delete unconditionally', () => {
    const v = new DecisionService().decide(makeRisk('MALICIOUS', 95, 30, { isMalware: true }), makeCtxWithRules([]));
    expect(v.label).toBe('MALICIOUS');
    expect(v.action).toBe('delete');
  });

  it('✅ confidence between 0 and 100', () => {
    const v = new DecisionService().decide(
      makeRisk('PHISHING', 80, 75, { isPhishing: true }),
      makeCtxWithRules([{ id: 'urgent_phishing_language' }]),
    );
    expect(v.confidence).toBeGreaterThanOrEqual(0);
    expect(v.confidence).toBeLessThanOrEqual(100);
  });

  it('✅ triggeredRules populated from ctx.ruleResults', () => {
    const ctx = makeCtxWithRules([
      { id: 'urgent_phishing_language' },
      { id: 'email_auth_failure' },
    ]);
    const v = new DecisionService().decide(makeRisk('SUSPICIOUS', 50, 60), ctx);
    expect(v.triggeredRules).toContain('urgent_phishing_language');
    expect(v.triggeredRules).toContain('email_auth_failure');
  });

  it('✅ recommendations populated for threats', () => {
    const v = new DecisionService().decide(
      makeRisk('PHISHING', 80, 75, { isPhishing: true }),
      makeCtxWithRules([]),
    );
    expect(Array.isArray(v.recommendations)).toBe(true);
    expect(v.recommendations.length).toBeGreaterThan(0);
  });

  it('✅ riskScore in verdict matches finalScore', () => {
    const v = new DecisionService().decide(makeRisk('SUSPICIOUS', 55, 60), makeCtxWithRules([]));
    expect(v.riskScore).toBe(55);
  });
});

// ─── Email Parser ─────────────────────────────────────────────────────────────

describe('EmailParserService — Edge Cases', () => {
  const parser = new EmailParserService();

  it('✅ Extracts base domain and full domain', () => {
    const p = parser.parse(makeRawEmail({ fromAddr: '"John" <john@paypal.com>' }));
    expect(p.fromDomain).toBe('paypal');
    expect(p.fromFullDomain).toBe('paypal.com');
  });

  it('✅ Extracts URLs from bodyHtml', () => {
    const p = parser.parse(makeRawEmail({
      bodyHtml: '<a href="https://evil.tk/steal">Click</a><a href="https://google.com">OK</a>',
    }));
    expect(p.urls.length).toBe(2);
    expect(p.urls.some(u => u.includes('evil.tk'))).toBe(true);
  });

  it('✅ hasAttachment=false when no attachments', () => {
    const p = parser.parse(makeRawEmail());
    expect(p.hasAttachment).toBe(false);
  });

  it('✅ isReplyThread=true for Re: subject', () => {
    const p = parser.parse(makeRawEmail({ subject: 'Re: Monthly invoice' }));
    expect(p.isReplyThread).toBe(true);
  });

  it('✅ Arabic reply → isReplyThread=true', () => {
    const p = parser.parse(makeRawEmail({ subject: 'رد: تحديث المشروع' }));
    expect(p.isReplyThread).toBe(true);
  });

  it('✅ Empty fromAddr → fromDomain=null (no crash)', () => {
    const p = parser.parse(makeRawEmail({ fromAddr: '' }));
    expect(p.fromDomain).toBeNull();
    expect(p.fromFullDomain).toBeNull();
  });

  it('✅ emailId preserved as string', () => {
    const p = parser.parse(makeRawEmail({ emailId: 42 }));
    expect(p.emailId).toBe('42');
  });
});
