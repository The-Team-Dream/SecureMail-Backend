// ─────────────────────────────────────────────────────────────────────────────
// header.rules.spec.ts
// Unit tests for HeaderRules — Rule 23: Conversation Hijacking
// ─────────────────────────────────────────────────────────────────────────────

import { HeaderRules } from '../rules/header.rules';
import { EmailContentForClassification } from '../classification.service';

const rules = new HeaderRules();

function makeEmail(overrides: Partial<EmailContentForClassification>): EmailContentForClassification {
  return {
    subject:  'Hello',
    fromAddr: 'sender@example.com',
    bodyText: '',
    ...overrides,
  };
}

function check(email: Partial<EmailContentForClassification>): { score: number; reasons: string[] } {
  const reasons: string[] = [];
  const score = rules.check(makeEmail(email), reasons);
  return { score, reasons };
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule 23 — Conversation Hijacking
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 23 — Conversation Hijacking', () => {

  // ── Positive cases (Re: prefix) ───────────────────────────────────────────

  it('✅ flags Re: subject + wire transfer request', () => {
    const { score, reasons } = check({
      subject:  'Re: Q4 Budget Review',
      bodyText: 'Following up on our discussion — please process a wire transfer to the new account.',
    });
    expect(score).toBeGreaterThan(0);
    expect(reasons).toContain('conversation_hijacking_attempt');
  });

  it('✅ flags Re: subject + bank account change', () => {
    const { reasons } = check({
      subject:  'Re: Invoice #4521',
      bodyText: 'Please update payment details to our new bank account urgently.',
    });
    expect(reasons).toContain('conversation_hijacking_attempt');
  });

  it('✅ flags Re: subject + urgent payment', () => {
    const { reasons } = check({
      subject:  'Re: Project Proposal',
      bodyText: 'Hi, just following up. We need an urgent payment processed today.',
    });
    expect(reasons).toContain('conversation_hijacking_attempt');
  });

  it('✅ flags Re: subject + updated invoice info', () => {
    const { reasons } = check({
      subject:  'Re: Contract Renewal',
      bodyText: 'Please note our updated billing info for the next payment.',
    });
    expect(reasons).toContain('conversation_hijacking_attempt');
  });

  // ── Positive cases (Fwd: prefix) ─────────────────────────────────────────

  it('✅ flags Fwd: subject + wire transfer', () => {
    const { reasons } = check({
      subject:  'Fwd: Supplier Payment',
      bodyText: 'Forwarding this — please arrange a bank transfer to the account below.',
    });
    expect(reasons).toContain('conversation_hijacking_attempt');
  });

  it('✅ flags FW: subject (Outlook format)', () => {
    const { reasons } = check({
      subject:  'FW: Outstanding Invoice',
      bodyText: 'Please change of account details for the payment.',
    });
    expect(reasons).toContain('conversation_hijacking_attempt');
  });

  // ── Positive cases (In-Reply-To header) ──────────────────────────────────

  it('✅ flags In-Reply-To header + financial request (no Re: prefix)', () => {
    const { reasons } = check({
      subject:  'Payment Update',
      bodyText: 'Please process a wire transfer to our updated bank account.',
      headers:  { 'in-reply-to': '<abc123@company.com>' },
    });
    expect(reasons).toContain('conversation_hijacking_attempt');
  });

  it('✅ flags In-Reply-To + account change request', () => {
    const { reasons } = check({
      subject:  'Follow-up',
      bodyText: 'Hi, please update payment details to the new bank account.',
      headers:  { 'In-Reply-To': '<thread-id-456@mail.com>' },
    });
    expect(reasons).toContain('conversation_hijacking_attempt');
  });

  // ── Negative cases ────────────────────────────────────────────────────────

  it('❌ does NOT flag Re: subject with no financial content', () => {
    const { reasons } = check({
      subject:  'Re: Team Lunch Friday',
      bodyText: 'Sounds great! See you at 1pm.',
    });
    expect(reasons).not.toContain('conversation_hijacking_attempt');
  });

  it('❌ does NOT flag financial request with no reply thread', () => {
    // مفيش Re: prefix ومفيش In-Reply-To header
    const { reasons } = check({
      subject:  'Invoice Payment',
      bodyText: 'Please process a wire transfer to our account.',
    });
    expect(reasons).not.toContain('conversation_hijacking_attempt');
  });

  it('❌ does NOT flag Re: with only general follow-up language', () => {
    const { reasons } = check({
      subject:  'Re: Project Update',
      bodyText: 'Thanks for the update. I will review and get back to you tomorrow.',
    });
    expect(reasons).not.toContain('conversation_hijacking_attempt');
  });

  it('❌ does NOT flag In-Reply-To with no financial keywords', () => {
    const { reasons } = check({
      subject:  'Follow-up',
      bodyText: 'Just checking in on the status of the project.',
      headers:  { 'in-reply-to': '<abc123@company.com>' },
    });
    expect(reasons).not.toContain('conversation_hijacking_attempt');
  });
});
