// ─────────────────────────────────────────────────────────────────────────────
// link.rules.spec.ts
// Unit tests for LinkRules — Rules 9, 10, 12, 25, 26
// ─────────────────────────────────────────────────────────────────────────────

import { LinkRules } from '../rules/link.rules';
import { EmailContentForClassification } from '../classification.service';

const rules = new LinkRules();

function makeEmail(overrides: Partial<EmailContentForClassification>): EmailContentForClassification {
  return {
    subject:  'Test',
    fromAddr: 'sender@example.com',
    bodyText: '',
    bodyHtml: '',
    ...overrides,
  };
}

function check(email: Partial<EmailContentForClassification>): { score: number; reasons: string[] } {
  const reasons: string[] = [];
  const score = rules.check(makeEmail(email), reasons);
  return { score, reasons };
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule 9 — IP-based URLs
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 9 — IP-based URLs', () => {
  it('✅ flags http://192.168.1.1/login in body', () => {
    const { score, reasons } = check({ bodyText: 'Click here: http://192.168.1.1/login' });
    expect(score).toBeGreaterThan(0);
    expect(reasons).toContain('ip_based_url');
  });

  it('✅ flags IP URL in HTML body', () => {
    const { reasons } = check({
      bodyHtml: '<a href="http://91.234.56.78/steal">Click here</a>',
    });
    expect(reasons).toContain('ip_based_url');
  });

  it('✅ flags IP URL in subject', () => {
    const { reasons } = check({ subject: 'Verify at http://10.0.0.1/verify' });
    expect(reasons).toContain('ip_based_url');
  });

  it('❌ does NOT flag domain-based URL', () => {
    const { reasons } = check({ bodyText: 'Visit https://paypal.com for details.' });
    expect(reasons).not.toContain('ip_based_url');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 10 — Shortened URLs
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 10 — Shortened URLs', () => {
  it('✅ flags bit.ly in body', () => {
    const { score, reasons } = check({ bodyText: 'Click here: https://bit.ly/3xyz' });
    expect(score).toBeGreaterThan(0);
    expect(reasons).toContain('shortened_url');
  });

  it('✅ flags tinyurl.com', () => {
    const { reasons } = check({ bodyText: 'Visit tinyurl.com/abc123' });
    expect(reasons).toContain('shortened_url');
  });

  it('✅ flags ow.ly', () => {
    const { reasons } = check({ bodyText: 'More info at ow.ly/xyz' });
    expect(reasons).toContain('shortened_url');
  });

  it('❌ does NOT flag full domain URL', () => {
    const { reasons } = check({ bodyText: 'Visit https://amazon.com/product/12345' });
    expect(reasons).not.toContain('shortened_url');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 12 — Link Text Mismatch
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 12 — HTML Link Text Mismatch', () => {
  it('✅ flags link text "amazon.com" pointing to evil.com', () => {
    const { score, reasons } = check({
      bodyHtml: '<a href="https://evil-phishing.com/steal">amazon.com</a>',
    });
    expect(score).toBeGreaterThan(0);
    expect(reasons).toContain('html_link_text_mismatch');
  });

  it('✅ flags link text "paypal.com" pointing to attacker.ru', () => {
    const { reasons } = check({
      bodyHtml: '<a href="https://attacker.ru/login">paypal.com</a>',
    });
    expect(reasons).toContain('html_link_text_mismatch');
  });

  it('❌ does NOT flag matching domain in text and href', () => {
    const { reasons } = check({
      bodyHtml: '<a href="https://amazon.com/orders">amazon.com</a>',
    });
    expect(reasons).not.toContain('html_link_text_mismatch');
  });

  it('❌ does NOT flag link text that is not a domain', () => {
    const { reasons } = check({
      bodyHtml: '<a href="https://evil.com/steal">Click here to verify</a>',
    });
    expect(reasons).not.toContain('html_link_text_mismatch');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 25 — HTML Obfuscation
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 25 — HTML Obfuscation', () => {
  it('✅ flags zero-width characters', () => {
    const { score, reasons } = check({
      bodyHtml: `<p>Pay\u200Bpal verify your account</p>`,
    });
    expect(score).toBeGreaterThan(0);
    expect(reasons).toContain('html_obfuscation_phishing');
  });

  it('✅ flags display:none CSS hiding', () => {
    const { reasons } = check({
      bodyHtml: '<span style="display:none">hidden spam text</span><p>Real content</p>',
    });
    expect(reasons).toContain('html_obfuscation_phishing');
  });

  it('✅ flags font-size:0 trick', () => {
    const { reasons } = check({
      bodyHtml: '<span style="font-size:0">spam filler</span>',
    });
    expect(reasons).toContain('html_obfuscation_phishing');
  });

  it('✅ flags excessive HTML comments (> 5)', () => {
    const manyComments = Array(7).fill('<!-- comment -->').join('') + '<p>Real content</p>';
    const { reasons } = check({ bodyHtml: manyComments });
    expect(reasons).toContain('html_obfuscation_phishing');
  });

  it('❌ does NOT flag clean HTML', () => {
    const { reasons } = check({
      bodyHtml: '<p>Hello <b>John</b>, please review the <a href="https://company.com">report</a>.</p>',
    });
    expect(reasons).not.toContain('html_obfuscation_phishing');
  });

  it('❌ does NOT flag 2 HTML comments (normal)', () => {
    const { reasons } = check({
      bodyHtml: '<!-- header --><!-- footer --><p>Clean content here.</p>',
    });
    expect(reasons).not.toContain('html_obfuscation_phishing');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 26 — Base64 Encoded URLs
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 26 — Base64 Encoded URLs', () => {
  it('✅ flags data:text/html;base64 in href', () => {
    const { score, reasons } = check({
      bodyHtml: `<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">Click</a>`,
    });
    expect(score).toBeGreaterThan(0);
    expect(reasons).toContain('base64_encoded_url');
  });

  it('✅ flags Base64-encoded URL in plain text body', () => {
    // aHR0cHM6Ly9waGlzaGluZy5zaXRlL3N0ZWFs = https://phishing.site/steal
    const b64 = 'aHR0cHM6Ly9waGlzaGluZy5zaXRlL3N0ZWFs';
    const { score, reasons } = check({ bodyText: `Please visit: ${b64}` });
    expect(score).toBeGreaterThan(0);
    expect(reasons).toContain('base64_encoded_url');
  });

  it('❌ does NOT flag normal email without Base64', () => {
    const { reasons } = check({
      bodyText: 'Please visit https://company.com for more details.',
      bodyHtml: '<p>Visit <a href="https://company.com">company.com</a></p>',
    });
    expect(reasons).not.toContain('base64_encoded_url');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Regression tests — fixes from v7/v9
// يوثّقوا الـ fixes عشان لو حد غيّر الـ logic تاني الـ tests يجيبه
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 12 — Regression: tracking subdomain vs base domain', () => {

  it('❌ does NOT flag em.paypal.com vs paypal.com (same base domain)', () => {
    // em.paypal.com هو الـ email sending subdomain الرسمي لـ PayPal
    // كان بيتفلق لأن em.paypal.com !== paypal.com (full hostname comparison)
    // الصح: extractBaseDomain(em.paypal.com) = paypal = extractBaseDomain(paypal.com)
    const { reasons } = check({
      bodyHtml: `<a href="https://em.paypal.com/track">paypal.com</a>`,
    });
    expect(reasons).not.toContain('html_link_text_mismatch');
  });

  it('✅ DOES flag different base domains (tracking.different-service.com vs company.com)', () => {
    // بيوثّق إن الـ base domain comparison شغالة بشكل صح
    // different-service.com !== company.com → يتفلق كـ mismatch — ده الـ intended behavior
    // الـ fix من v7 كان على tracking.paypal.com vs paypal.com (same base) — مش هنا
    const { reasons } = check({
      fromAddr: 'newsletter@mailchimp.com',
      bodyHtml: `<a href="https://tracking.different-service.com/click">company.com</a>`,
    });
    expect(reasons).toContain('html_link_text_mismatch');
  });
});

describe('Rule 25 — Regression: HTML entity obfuscation brand check', () => {

  it('❌ does NOT flag mailchimp.com sender with &#160; and paypal mention', () => {
    // &#160; = non-breaking space — شائع جداً في HTML emails الشرعية
    // newsletter من mailchimp بتذكر PayPal كـ payment method → مش phishing
    const { reasons } = check({
      fromAddr: 'newsletter@mailchimp.com',
      bodyHtml: `<p>We&#160;accept&#160;PayPal&#160;payments</p>`,
    });
    expect(reasons).not.toContain('html_obfuscation_phishing');
  });

  it('✅ DOES flag google.com sender with entity-encoded paypal content', () => {
    // &#112;&#97;&#121;&#112;&#97;&#108; = "paypal" — entity encoding للتهرب من الـ detection
    // الـ sender هو google.com لكن الـ body فيه PayPal encoded — ده spoofing
    // الصح: officialBases لـ 'paypal' مش بتشمل google → يتفلق
    const { reasons } = check({
      fromAddr: 'support@google.com',
      bodyHtml: `<p>Verify your &#112;&#97;&#121;&#112;&#97;&#108; account immediately</p>`,
    });
    expect(reasons).toContain('html_obfuscation_phishing');
  });

  it('✅ flags hex entity encoding — &#x70;&#x61;&#x79;... = "paypal" (IMP FIX)', () => {
    // Phishers use hex encoding to bypass scanners that only handle decimal
    // &#x70;&#x61;&#x79;&#x70;&#x61;&#x6c; = "paypal"
    // Old code only decoded decimal &#112; — this test validates hex decode was added
    const { reasons } = check({
      fromAddr: 'support@attacker.com',
      bodyHtml: '<p>Verify your &#x70;&#x61;&#x79;&#x70;&#x61;&#x6c; account now</p>',
    });
    expect(reasons).toContain('html_obfuscation_phishing');
  });

  it('❌ does NOT flag Mailchimp sender with &#160; only (no brand obfuscation)', () => {
    // &#160; = non-breaking space — extremely common in HTML emails
    // Mailchimp is trusted ESP → skip obfuscation check
    const { reasons } = check({
      fromAddr: 'news@mailchimp.com',
      bodyHtml: '<p>Thank&#160;you&#160;for&#160;subscribing</p>',
    });
    expect(reasons).not.toContain('html_obfuscation_phishing');
  });
});
