// ─────────────────────────────────────────────────────────────────────────────
// security/tests/calibration-corpus.spec.ts
//
// FIX-6: Calibration Corpus Tests
//
// المشكلة: Scoring formula تغيرت جذرياً (2-score → 6-component)
// لكن لا يوجد tests تتأكد إن benign emails مش بتاخد score >= 41 (SUSPICIOUS tier)
//
// هذا الملف يحتوي 25 benign email sample:
//   - كل email لازم يرجع SAFE (0-20) أو SPAM max (21-40)
//   - أي email يرجع SUSPICIOUS/PHISHING/MALICIOUS = test fails = false positive
//
// Run: npx jest calibration-corpus --no-coverage
// ─────────────────────────────────────────────────────────────────────────────

import { ScoringService }    from '../pipeline/scoring/scoring.service';
import { CorrelationService } from '../pipeline/detection/correlation-engine/correlation.service';
import { DecisionService }   from '../pipeline/decision/decision.service';
import { EmailParserService, RawEmailInput } from '../pipeline/email-parser/email-parser.service';
import { AuthenticationService }   from '../pipeline/authentication/authentication.service';
import { DetectionContext, UNKNOWN_REPUTATION, DEFAULT_BEHAVIOR } from '../pipeline/detection/rule-engine/detection-context';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function makeContext(overrides: Partial<RawEmailInput> = {}) {
  const parser = new EmailParserService();
  const parsed = parser.parse({
    emailId: '1', messageId: '<test@ok.com>', mailBoxId: 1,
    fromAddr: 'sender@example.com', fromName: 'Test Sender',
    toAddr: ['user@company.com'], subject: 'Hello',
    bodyText: 'This is a normal email.', bodyHtml: null,
    receivedAt: new Date(), ...overrides,
  });
  const auth = new AuthenticationService().analyze(parsed);
  return new DetectionContext(parsed, auth, UNKNOWN_REPUTATION, DEFAULT_BEHAVIOR, null);
}

function scoreCtx(ctx: DetectionContext) {
  const scorer      = new ScoringService();
  const correlator  = new CorrelationService();
  const correlation = correlator.correlate(ctx);
  ctx.correlation   = correlation;
  return scorer.computeRisk(ctx, null);
}

// ─── Corpus ───────────────────────────────────────────────────────────────────

describe('FIX-6: Calibration Corpus — 25 benign emails must be SAFE or SPAM max', () => {

  const ALLOWED_TIERS = new Set(['SAFE', 'SPAM']);

  // ── Group 1: Plain transactional emails ──────────────────────────────────
  it('01 — Plain meeting invite (no signals)', () => {
    const ctx = makeContext({ subject: 'Meeting tomorrow at 3pm', bodyText: 'Hi, can we meet tomorrow?' });
    const r   = scoreCtx(ctx);
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  it('02 — Standard newsletter with unsubscribe', () => {
    const ctx = makeContext({
      fromAddr: 'news@mailchimp.com',
      subject: 'Weekly Digest — Top stories this week',
      bodyText: 'Here are the top stories. To unsubscribe click here.',
    });
    const r = scoreCtx(ctx);
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  it('03 — GitHub PR notification', () => {
    const ctx = makeContext({
      fromAddr: 'notifications@github.com',
      subject: 'PR #42: Fix memory leak in parser',
      bodyText: 'User opened pull request #42. Review at https://github.com/org/repo/pull/42',
    });
    const r = scoreCtx(ctx);
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  it('04 — Invoice PDF from known vendor (legit)', () => {
    const ctx = makeContext({
      fromAddr: 'billing@adobe.com',
      subject: 'Your invoice for Creative Cloud — May 2026',
      bodyText: 'Thank you for your subscription. Your invoice is attached.',
      attachments: [{ filename: 'invoice-2026-05.pdf', mimeType: 'application/pdf', size: 80000, storagePath: '/tmp/inv.pdf' }],
    });
    const r = scoreCtx(ctx);
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  it('05 — Order shipping confirmation', () => {
    const ctx = makeContext({
      fromAddr: 'shipping@amazon.com',
      subject: 'Your order has shipped — tracking #TBA12345',
      bodyText: 'Your order has been dispatched. Track your package using the link.',
    });
    const r = scoreCtx(ctx);
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  it('06 — Slack workspace invite', () => {
    const ctx = makeContext({
      fromAddr: 'no-reply@slack.com',
      subject: 'You have been invited to join Engineering workspace',
      bodyText: 'Click the button to accept your invitation to the Engineering Slack workspace.',
    });
    const r = scoreCtx(ctx);
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  it('07 — Google Calendar event', () => {
    const ctx = makeContext({
      fromAddr: 'calendar-notification@google.com',
      subject: 'Team sync - Tuesday 10am',
      bodyText: 'This is a reminder for your upcoming event. https://calendar.google.com/event?eid=abc',
    });
    const r = scoreCtx(ctx);
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  // ── Group 2: Emails with urgent-sounding subject but legitimate content ──
  it('08 — Legitimate password reset from known service', () => {
    const ctx = makeContext({
      fromAddr: 'security@google.com',
      subject: 'Reset your Google password',
      bodyText: 'We received a request to reset your password. If you made this request, click here.',
      headers: { 'authentication-results': 'spf=pass dkim=pass dmarc=pass' },
    });
    const r = scoreCtx(ctx);
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  it('09 — Zoom meeting reminder with join link', () => {
    const ctx = makeContext({
      fromAddr: 'no-reply@zoom.us',
      subject: 'Reminder: Standup in 10 minutes',
      bodyText: 'Join your Zoom meeting: https://zoom.us/j/123456789',
    });
    const r = scoreCtx(ctx);
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  it('10 — LinkedIn connection request', () => {
    const ctx = makeContext({
      fromAddr: 'notifications@linkedin.com',
      subject: 'Ahmed accepted your connection request',
      bodyText: 'Ahmed Mohamed has accepted your connection. View their profile on LinkedIn.',
    });
    const r = scoreCtx(ctx);
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  // ── Group 3: Emails with attachments ─────────────────────────────────────
  it('11 — Legitimate .zip attachment from known sender', () => {
    const ctx = makeContext({
      fromAddr: 'dev@trusted-company.com',
      subject: 'Design assets for sprint 3',
      bodyText: 'Hi, attached are the design assets for sprint 3 review.',
      attachments: [{ filename: 'sprint3-assets.zip', mimeType: 'application/zip', size: 5000000, storagePath: '/tmp/s3.zip' }],
    });
    const r = scoreCtx(ctx);
    // zip gets minor score but should stay ≤ SPAM
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  it('12 — Word document report attachment', () => {
    const ctx = makeContext({
      fromAddr: 'analyst@research-firm.com',
      subject: 'Q1 2026 Market Analysis Report',
      bodyText: 'Please find the Q1 market analysis report attached for your review.',
      attachments: [{ filename: 'Q1-report.docx', mimeType: 'application/vnd.openxmlformats-officedocument', size: 250000, storagePath: '/tmp/rpt.docx' }],
    });
    const r = scoreCtx(ctx);
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  // ── Group 4: Emails with URLs ─────────────────────────────────────────────
  it('13 — Email with standard https links', () => {
    const ctx = makeContext({
      fromAddr: 'hello@example.com',
      subject: 'Check out this article',
      bodyHtml: '<p>Here is an interesting article: <a href="https://www.bbc.com/news/article-123">Read more</a></p>',
      bodyText: 'Here is an interesting article: https://www.bbc.com/news/article-123',
    });
    const r = scoreCtx(ctx);
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  it('14 — SaaS trial confirmation email', () => {
    const ctx = makeContext({
      fromAddr: 'hello@stripe.com',
      subject: 'Welcome to Stripe — Your account is ready',
      bodyText: 'Your Stripe account is ready. Log in at https://dashboard.stripe.com to get started.',
      bodyHtml: '<p>Your Stripe account is ready. <a href="https://dashboard.stripe.com">Log in</a></p>',
    });
    const r = scoreCtx(ctx);
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  // ── Group 5: Arabic language legitimate emails ────────────────────────────
  it('15 — Arabic transactional email (Egyptian bank statement)', () => {
    const ctx = makeContext({
      fromAddr: 'statements@cib.com.eg',
      subject: 'كشف حساب شهر مايو 2026',
      bodyText: 'عزيزي العميل، يرجى الاطلاع على كشف حسابك لشهر مايو 2026.',
    });
    const r = scoreCtx(ctx);
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  it('16 — Arabic newsletter (no suspicious content)', () => {
    const ctx = makeContext({
      fromAddr: 'news@youm7.com',
      subject: 'نشرة اليوم الإخبارية — أبرز الأخبار',
      bodyText: 'مرحباً بكم في النشرة الإخبارية اليومية. للإلغاء الاشتراك اضغط هنا.',
    });
    const r = scoreCtx(ctx);
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  // ── Group 6: Edge cases that historically caused false positives ──────────
  it('17 — Reply thread with budget discussion (not BEC)', () => {
    const ctx = makeContext({
      subject: 'Re: Q3 budget planning',
      inReplyTo: '<prev@company.com>',
      bodyText: 'As discussed, the Q3 budget is 500k. Let me know if you need the breakdown.',
    });
    const r = scoreCtx(ctx);
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  it('18 — Security team internal alert (not phishing)', () => {
    const ctx = makeContext({
      fromAddr: 'security@company.com',
      subject: 'Security alert: New login from Cairo',
      bodyText: 'We detected a new sign-in to your account from Cairo, Egypt. If this was you, no action is needed.',
      headers: { 'authentication-results': 'spf=pass dkim=pass dmarc=pass' },
    });
    const r = scoreCtx(ctx);
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  it('19 — IT department announcement', () => {
    const ctx = makeContext({
      fromAddr: 'it@company.com',
      subject: 'Scheduled maintenance — password reset required',
      bodyText: 'Due to scheduled maintenance this weekend, all users must reset their passwords by Friday.',
      headers: { 'authentication-results': 'spf=pass dkim=pass' },
    });
    const r = scoreCtx(ctx);
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  it('20 — Short email with only greeting', () => {
    const ctx = makeContext({
      subject: 'Hi!',
      bodyText: 'Hope you are doing well. Let\'s catch up soon.',
    });
    const r = scoreCtx(ctx);
    expect(r.tier).toBe('SAFE');
  });

  // ── Group 7: Borderline — should be SPAM max, not SUSPICIOUS+ ────────────
  it('21 — Promotional email with "limited time" (marketing spam)', () => {
    const ctx = makeContext({
      fromAddr: 'promo@deals.com',
      subject: 'LIMITED TIME: 80% off everything!',
      bodyText: 'Act now! This exclusive offer expires soon. Buy now and save 80%! Guaranteed results. 100% free shipping.',
    });
    const r = scoreCtx(ctx);
    // Marketing spam is OK to be SPAM — but not SUSPICIOUS
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  it('22 — Crypto newsletter (not scam)', () => {
    const ctx = makeContext({
      fromAddr: 'news@coinbase.com',
      subject: 'Bitcoin weekly update — Market analysis',
      bodyText: 'Here is your weekly crypto market update from Coinbase.',
    });
    const r = scoreCtx(ctx);
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  it('23 — Email with multiple URLs to known domains', () => {
    const ctx = makeContext({
      fromAddr: 'hello@medium.com',
      subject: 'Your weekly reading list',
      bodyHtml: '<p>Read: <a href="https://medium.com/a">Article 1</a>, <a href="https://medium.com/b">Article 2</a>, <a href="https://twitter.com/x">Tweet</a></p>',
    });
    const r = scoreCtx(ctx);
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  it('24 — Legal department email with formal language', () => {
    const ctx = makeContext({
      fromAddr: 'legal@lawfirm.com',
      subject: 'Confidential: Contract review required',
      bodyText: 'Please review the attached contract and confirm your approval at your earliest convenience. This matter is confidential.',
    });
    const r = scoreCtx(ctx);
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  it('25 — SPF softfail but benign content (common with forwarded emails)', () => {
    const ctx = makeContext({
      fromAddr: 'friend@gmail.com',
      subject: 'Forwarded article you might like',
      bodyText: 'Hey, thought you might find this interesting. Check it out.',
      headers: { 'authentication-results': 'spf=softfail dkim=pass dmarc=none' },
    });
    const r = scoreCtx(ctx);
    // softfail alone should not push to SUSPICIOUS
    expect(ALLOWED_TIERS.has(r.tier)).toBe(true);
  });

  // ── Summary test: all pass rate ───────────────────────────────────────────
  it('CORPUS SUMMARY — false positive rate must be 0%', () => {
    const corpus: Array<[string, Partial<RawEmailInput>]> = [
      ['plain greeting',         { subject: 'Hi', bodyText: 'Hello there!' }],
      ['github notification',    { fromAddr: 'noreply@github.com', subject: 'New issue opened', bodyText: 'Issue #99 opened in your repo.' }],
      ['calendar reminder',      { fromAddr: 'calendar@google.com', subject: 'Reminder: 1:1 in 15 min', bodyText: 'Your meeting starts soon.' }],
      ['slack notification',     { fromAddr: 'feedback@slack.com', subject: 'New message in #general', bodyText: 'Ahmed posted in #general: "Good morning!"' }],
      ['job offer acceptance',   { fromAddr: 'hr@bigcorp.com', subject: 'Your offer letter', bodyText: 'Congratulations! We are pleased to offer you the position.' }],
    ];

    let falsePositives = 0;
    for (const [label, overrides] of corpus) {
      const ctx = makeContext(overrides);
      const r   = scoreCtx(ctx);
      if (!ALLOWED_TIERS.has(r.tier)) {
        falsePositives++;
        console.error(`FALSE POSITIVE: "${label}" scored ${r.tier} (score: ${r.finalScore})`);
      }
    }

    expect(falsePositives).toBe(0);
  });
});
