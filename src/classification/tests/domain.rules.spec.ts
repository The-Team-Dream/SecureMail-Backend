// ─────────────────────────────────────────────────────────────────────────────
// domain.rules.spec.ts
// Unit tests for DomainRules — Rules 6, 11, 17, 19, 20, 24
// ─────────────────────────────────────────────────────────────────────────────

import { DomainRules } from '../rules/domain.rules';
import { EmailContentForClassification } from '../classification.service';

// ─── Helpers ──────────────────────────────────────────────────────────────────
const rules = new DomainRules();

function makeEmail(overrides: Partial<EmailContentForClassification>): EmailContentForClassification {
  return {
    subject:  'Test Email',
    fromAddr: 'sender@example.com',
    bodyText: 'Hello this is a test.',
    ...overrides,
  };
}

function check(email: Partial<EmailContentForClassification>): Promise<{ score: number; reasons: string[] }> {
  const reasons: string[] = [];
  return rules.check(makeEmail(email), reasons).then(score => ({ score, reasons }));
}

beforeAll(() => {
  jest.spyOn(global, 'fetch').mockResolvedValue({
    ok: true,
    json: async () => ({
      events: [
        {
          eventAction: 'registration',
          eventDate: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000).toISOString(), // 1 year ago
        },
      ],
    }),
  } as Response);
});

afterAll(() => {
  jest.restoreAllMocks();
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 6 — Typosquatting
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 6 — Typosquatting', () => {
  it('✅ flags paypa1.com as typosquatting', async () => {
    const { score, reasons } = await check({ fromAddr: 'support@paypa1.com' });
    expect(score).toBeGreaterThan(0);
    expect(reasons).toContain('typosquatting_domain');
  });

  it('✅ flags paypall.com (extra char)', async () => {
    const { reasons } = await check({ fromAddr: 'noreply@paypall.com' });
    expect(reasons).toContain('typosquatting_domain');
  });

  it('✅ flags microsofft.com', async () => {
    const { reasons } = await check({ fromAddr: 'support@microsofft.com' });
    expect(reasons).toContain('typosquatting_domain');
  });

  it('❌ does NOT flag paypal.com (official domain)', async () => {
    const { reasons } = await check({ fromAddr: 'support@paypal.com' });
    expect(reasons).not.toContain('typosquatting_domain');
  });

  it('❌ does NOT flag mail.paypal.com (subdomain)', async () => {
    const { reasons } = await check({ fromAddr: 'support@mail.paypal.com' });
    expect(reasons).not.toContain('typosquatting_domain');
  });

  it('❌ does NOT flag unknown-company.com (not a brand)', async () => {
    const { reasons } = await check({ fromAddr: 'hr@unknown-company.com' });
    expect(reasons).not.toContain('typosquatting_domain');
  });

  // Regression: brand-as-subdomain-prefix fix
  it('✅ flags paypal.attacker.ru (brand as subdomain prefix)', async () => {
    // extractBaseDomain → 'attacker' → levenshtein('attacker','paypal') = 7 → يفوت الـ fuzzy check
    // الحل: fullDomain.startsWith('paypal.') && senderBase !== 'paypal'
    const { reasons } = await check({ fromAddr: 'support@paypal.attacker.ru' });
    expect(reasons).toContain('typosquatting_domain');
  });

  it('✅ flags google.phishing-site.com (brand as subdomain prefix)', async () => {
    const { reasons } = await check({ fromAddr: 'noreply@google.phishing-site.com' });
    expect(reasons).toContain('typosquatting_domain');
  });

  it('❌ does NOT flag paypalbank.com (brand contained but not as prefix)', async () => {
    // 'paypalbank'.startsWith('paypal.') = false → لا يتفلق بالـ new check
    // levenshtein('paypalbank', 'paypal') = 4 > 2 → لا يتفلق بالـ fuzzy check
    const { reasons } = await check({ fromAddr: 'info@paypalbank.com' });
    expect(reasons).not.toContain('typosquatting_domain');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 11 — Suspicious TLDs
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 11 — Suspicious TLDs', () => {
  it('✅ flags .tk domain (high risk)', async () => {
    const { score, reasons } = await check({ fromAddr: 'sender@phishing.tk' });
    expect(score).toBeGreaterThanOrEqual(15);
    expect(reasons).toContain('suspicious_sender_tld');
  });

  it('✅ flags .ml domain (high risk)', async () => {
    const { reasons } = await check({ fromAddr: 'sender@free-stuff.ml' });
    expect(reasons).toContain('suspicious_sender_tld');
  });

  it('✅ flags unknown .xyz domain (medium risk)', async () => {
    const { score, reasons } = await check({ fromAddr: 'sender@random-site.xyz' });
    expect(score).toBeGreaterThan(0);
    expect(reasons).toContain('suspicious_sender_tld');
  });

  it('❌ does NOT flag .com domain', async () => {
    const { reasons } = await check({ fromAddr: 'sender@company.com' });
    expect(reasons).not.toContain('suspicious_sender_tld');
  });

  it('❌ does NOT flag .org domain', async () => {
    const { reasons } = await check({ fromAddr: 'sender@nonprofit.org' });
    expect(reasons).not.toContain('suspicious_sender_tld');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 17 — Homoglyph / Unicode Spoofing
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 17 — Homoglyph Spoofing', () => {
  it('✅ flags Cyrillic "а" in paypal domain', async () => {
    // \u0430 = Cyrillic 'а' looks like Latin 'a'
    const { score, reasons } = await check({ fromAddr: 'support@p\u0430ypal.com' });
    expect(score).toBeGreaterThan(0);
    expect(reasons).toContain('homoglyph_domain_spoofing');
  });

  it('✅ flags Cyrillic "е" in microsoft domain', async () => {
    // \u0435 = Cyrillic 'е' looks like Latin 'e'
    const { score, reasons } = await check({ fromAddr: 'support@micros\u043eft.com' });
    expect(score).toBeGreaterThan(0);
    expect(reasons).toContain('homoglyph_domain_spoofing');
  });

  it('❌ does NOT flag clean ASCII domain', async () => {
    const { reasons } = await check({ fromAddr: 'support@paypal.com' });
    expect(reasons).not.toContain('homoglyph_domain_spoofing');
  });

  it('✅ flags Cyrillic у (U+0443) — paypal.com with Cyrillic y was undetected before fix', async () => {
    // BUG FIX: HOMOGLYPH_MAP \u0443 → y was missing
    // attacker registers paуpal.com (Cyrillic у) → bypassed detection
    const { reasons } = await check({ fromAddr: 'support@paуpal.com' });
    expect(reasons).toContain('homoglyph_domain_spoofing');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 20 — SPF / DKIM / DMARC
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 20 — Email Auth Failure (SPF/DKIM/DMARC)', () => {
  it('✅ flags SPF fail', async () => {
    const { score, reasons } = await check({
      fromAddr: 'sender@paypal.com',
      headers: { 'authentication-results': 'spf=fail smtp.mailfrom=paypal.com' },
    });
    expect(score).toBeGreaterThan(0);
    expect(reasons).toContain('email_auth_failure');
  });

  it('✅ flags DKIM fail + DMARC fail (max penalty)', async () => {
    const { score, reasons } = await check({
      fromAddr: 'sender@paypal.com',
      headers: { 'authentication-results': 'spf=fail; dkim=fail; dmarc=fail' },
    });
    expect(score).toBeGreaterThanOrEqual(35);
    expect(reasons).toContain('email_auth_failure');
  });

  it('✅ flags SPF softfail', async () => {
    const { reasons } = await check({
      fromAddr: 'sender@example.com',
      headers: { 'authentication-results': 'spf=softfail' },
    });
    expect(reasons).toContain('email_auth_failure');
  });

  it('❌ does NOT flag SPF pass', async () => {
    const { reasons } = await check({
      fromAddr: 'sender@example.com',
      headers: { 'authentication-results': 'spf=pass; dkim=pass; dmarc=pass' },
    });
    expect(reasons).not.toContain('email_auth_failure');
  });

  it('❌ does NOT flag missing auth header', async () => {
    const { reasons } = await check({ fromAddr: 'sender@example.com' });
    expect(reasons).not.toContain('email_auth_failure');
  });

  // Regression tests: graduated auth scoring
  it('✅ spf=fail scores higher than spf=softfail', async () => {
    const failCheck = await check({ fromAddr: 'test@unknown.com', headers: { 'authentication-results': 'mx; spf=fail' }});
    const softCheck = await check({ fromAddr: 'test@unknown.com', headers: { 'authentication-results': 'mx; spf=softfail' }});
    expect(failCheck.score).toBeGreaterThan(softCheck.score);
  });

  it('❌ spf=none + dkim=none + dmarc=none → low score (small company, missing config)', async () => {
    // 3+4+4 = 11pts — مش بيتعدى الـ 30pts phishing threshold لوحده
    // كان قبل الـ fix: 15+15+20 = 50 → يتفلق كـ phishing false positive
    const { score } = await check({
      fromAddr: 'hello@small-startup.com',
      headers: { 'authentication-results': 'mx; spf=none; dkim=none; dmarc=none' },
    });
    expect(score).toBeLessThan(20);
    expect(score).toBeGreaterThan(0);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 24 — Lookalike Domain Attack
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 24 — Lookalike Domain Attack', () => {
  it('✅ flags secure-paypal-login.xyz', async () => {
    const { score, reasons } = await check({ fromAddr: 'support@secure-paypal-login.xyz' });
    expect(score).toBeGreaterThan(0);
    expect(reasons).toContain('lookalike_domain_attack');
  });

  it('✅ flags paypal-account-verify.com', async () => {
    const { reasons } = await check({ fromAddr: 'noreply@paypal-account-verify.com' });
    expect(reasons).toContain('lookalike_domain_attack');
  });

  it('✅ flags microsoft-support-alert.net', async () => {
    const { reasons } = await check({ fromAddr: 'help@microsoft-support-alert.net' });
    expect(reasons).toContain('lookalike_domain_attack');
  });

  it('❌ does NOT flag paypal.com (official)', async () => {
    const { reasons } = await check({ fromAddr: 'support@paypal.com' });
    expect(reasons).not.toContain('lookalike_domain_attack');
  });

  it('❌ does NOT flag domain with brand but no phishing keyword', async () => {
    const { reasons } = await check({ fromAddr: 'info@paypal-news.com' });
    // "news" is not a phishing keyword
    expect(reasons).not.toContain('lookalike_domain_attack');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 19 — Received Headers Chain
// السيناريو: email مدّعي إنه من PayPal بس الـ Received headers مش بتمر بـ paypal servers
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 19 — Suspicious Received Headers', () => {

  it('✅ flags PayPal email with no paypal.com in Received chain (string header)', async () => {
    const { score, reasons } = await check({
      fromAddr: 'support@paypal.com',
      headers: {
        'received': 'from attacker-mail.ru (attacker-mail.ru [1.2.3.4]) by mx.victim.com',
      },
    });
    expect(score).toBeGreaterThan(0);
    expect(reasons).toContain('suspicious_received_headers');
  });

  it('✅ flags PayPal email with Received as array — none from paypal servers', async () => {
    const { reasons } = await check({
      fromAddr: 'noreply@paypal.com',
      headers: {
        'received': [
          'from random-server.xyz by mx.victim.com',
          'from another-server.net by random-server.xyz',
        ],
      },
    });
    expect(reasons).toContain('suspicious_received_headers');
  });

  it('❌ does NOT flag PayPal email with paypal.com in Received chain', async () => {
    const { reasons } = await check({
      fromAddr: 'support@paypal.com',
      headers: {
        'received': 'from mx1.paypal.com (mx1.paypal.com [66.211.168.0]) by mx.victim.com',
      },
    });
    expect(reasons).not.toContain('suspicious_received_headers');
  });

  it('❌ does NOT flag unknown sender — rule only checks brand senders', async () => {
    // Rule 19 بتشتغل بس لو الـ sender بيدّعي إنه brand معروف
    const { reasons } = await check({
      fromAddr: 'newsletter@random-company.com',
      headers: {
        'received': 'from random-server.xyz by mx.victim.com',
      },
    });
    expect(reasons).not.toContain('suspicious_received_headers');
  });

  it('❌ does NOT flag email with no headers', async () => {
    const { reasons } = await check({
      fromAddr: 'support@paypal.com',
    });
    expect(reasons).not.toContain('suspicious_received_headers');
  });
});
