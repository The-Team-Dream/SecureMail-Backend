// ─────────────────────────────────────────────────────────────────────────────
// security/tests/calibration-corpus.spec.ts
// 25 benign emails — must all return SAFE or SPAM max (no false positives)
// ─────────────────────────────────────────────────────────────────────────────

import { ScoringService }      from '../pipeline/8-scoring/scoring.service';
import { CorrelationService }  from '../pipeline/7-detection/correlation-engine/correlation.service';
import { EmailParserService }  from '../pipeline/1-email-parser/email-parser.service';
import { AuthenticationService } from '../pipeline/2-authentication/authentication.service';
import { DetectionContext }    from '../pipeline/7-detection/rule-engine/detection-context';
import { UNKNOWN_REPUTATION, DEFAULT_BEHAVIOR } from '../constants/default-signals.constant';
import { RawEmailInput }       from '../types/email.types';

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
  // مفيش phishingScore/spamScore على الـ ctx — الـ ScoringService بيحسبهم من ruleResults
  // الـ corpus emails بتعدي من غير rules مضافة = score من الـ reputation/auth فقط
  return new DetectionContext(parsed, auth, UNKNOWN_REPUTATION, DEFAULT_BEHAVIOR, null, null);
}

async function scoreCtx(ctx: DetectionContext) {
  ctx.setCorrelation(await new CorrelationService().correlate(ctx));
  return new ScoringService().computeRisk(ctx);
}

// ─── Corpus ───────────────────────────────────────────────────────────────────

describe('Calibration Corpus — 25 benign emails must be SAFE or SPAM max', () => {

  const ALLOWED = new Set(['SAFE', 'SPAM']);

  it('01 — Plain meeting invite', async () => {
    const r = await scoreCtx(makeContext({
      subject: 'Meeting tomorrow at 3pm',
      bodyText: 'Hi, can we meet tomorrow at 3pm?',
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('02 — Newsletter with unsubscribe', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'news@mailchimp.com',
      subject:  'Weekly Digest',
      bodyText: 'Top stories this week. To unsubscribe click here.',
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('03 — GitHub PR notification', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'notifications@github.com',
      subject:  'PR #42: Fix memory leak',
      bodyText: 'User opened pull request #42. https://github.com/org/repo/pull/42',
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('04 — Invoice PDF from known vendor', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr:    'billing@adobe.com',
      subject:     'Your invoice for Creative Cloud — May 2026',
      bodyText:    'Thank you for your subscription. Your invoice is attached.',
      attachments: [{ filename: 'invoice-2026-05.pdf', mimeType: 'application/pdf', size: 80000, storagePath: '/tmp/inv.pdf' }],
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('05 — Order shipping confirmation', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'shipping@amazon.com',
      subject:  'Your order has shipped',
      bodyText: 'Your order has been dispatched. Track your package.',
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('06 — Slack workspace invite', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'no-reply@slack.com',
      subject:  'You have been invited to join Engineering workspace',
      bodyText: 'Click to accept your invitation.',
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('07 — Google Calendar reminder', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'calendar-notification@google.com',
      subject:  'Team sync - Tuesday 10am',
      bodyText: 'Reminder for your upcoming event. https://calendar.google.com/event?eid=abc',
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('08 — Legitimate password reset from known service', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'security@google.com',
      subject:  'Reset your Google password',
      bodyText: 'We received a request to reset your password.',
      headers:  { 'authentication-results': 'spf=pass dkim=pass dmarc=pass' },
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('09 — Zoom meeting reminder', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'no-reply@zoom.us',
      subject:  'Reminder: Standup in 10 minutes',
      bodyText: 'Join your Zoom meeting: https://zoom.us/j/123456789',
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('10 — LinkedIn connection request', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'notifications@linkedin.com',
      subject:  'Ahmed accepted your connection request',
      bodyText: 'Ahmed Mohamed accepted your connection. View profile on LinkedIn.',
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('11 — Bank statement from known bank', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'noreply@cib.com.eg',
      subject:  'Your monthly statement is ready',
      bodyText: 'Your monthly account statement is now available.',
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('12 — Fawry payment confirmation', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'noreply@fawry.com',
      subject:  'Payment confirmed',
      bodyText: 'Your payment of 150 EGP has been processed successfully.',
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('13 — Regular colleague email', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'ahmed@company.com',
      fromName: 'Ahmed',
      subject:  'Lunch tomorrow?',
      bodyText: 'Are you free for lunch tomorrow at 1pm?',
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('14 — Job application confirmation', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'careers@microsoft.com',
      subject:  'We received your application',
      bodyText: 'Thank you for applying to Microsoft.',
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('15 — Dropbox file shared', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'no-reply@dropbox.com',
      subject:  'Ahmed shared a folder with you',
      bodyText: 'Ahmed shared "Project Files". https://www.dropbox.com/sh/abc123',
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('16 — AWS billing alert', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'billing@amazon.com',
      subject:  'Your AWS bill is ready',
      bodyText: 'Your monthly AWS bill is $45.20.',
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('17 — Stripe payment receipt', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'receipts@stripe.com',
      subject:  'Your receipt from Stripe',
      bodyText: 'Payment of $99 received.',
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('18 — Internal HR email', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'hr@mycompany.com',
      fromName: 'HR Department',
      subject:  'Updated leave policy',
      bodyText: 'Please review the updated annual leave policy.',
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('19 — Support ticket confirmation', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'support@zendesk.com',
      subject:  'Ticket #12345 opened',
      bodyText: 'Your support request has been received.',
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('20 — Apple receipt for App Store', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'no_reply@email.apple.com',
      subject:  'Your receipt from Apple',
      bodyText: 'Thank you for your purchase. Invoice amount: $0.99',
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('21 — Webinar invitation', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'events@hubspot.com',
      subject:  'You are invited: Marketing webinar on Thursday',
      bodyText: 'Join us for a free webinar. Register here.',
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('22 — University survey', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'noreply@university.edu',
      subject:  'Student satisfaction survey 2026',
      bodyText: 'Please complete our annual satisfaction survey.',
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('23 — Package delivery notification', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'noreply@dhl.com',
      subject:  'Your package is out for delivery',
      bodyText: 'Your shipment will be delivered today. https://www.dhl.com/track/123',
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('24 — Two-factor auth code', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'security@github.com',
      subject:  'Your GitHub authentication code',
      bodyText: 'Your authentication code is 123456. Expires in 15 minutes.',
      headers:  { 'authentication-results': 'spf=pass dkim=pass dmarc=pass' },
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });

  it('25 — Microsoft Teams notification', async () => {
    const r = await scoreCtx(makeContext({
      fromAddr: 'notifications@teams.microsoft.com',
      subject:  'Ahmed mentioned you in Engineering channel',
      bodyText: 'Ahmed: @you can you review the PR? https://teams.microsoft.com/l/message/abc',
    }));
    expect(ALLOWED.has(r.tier)).toBe(true);
  });
});
