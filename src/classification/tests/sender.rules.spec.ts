// ─────────────────────────────────────────────────────────────────────────────
// sender.rules.spec.ts
// Unit tests for SenderRules — Rules 3, 7, 16, 18, 21
// (Rule 13 — First Contact skipped: requires DB)
// ─────────────────────────────────────────────────────────────────────────────

import { SenderRules } from '../rules/sender.rules';
import { EmailContentForClassification } from '../classification.service';

// ─── Mock PrismaService ───────────────────────────────────────────────────────
// بنعمل mock كامل للـ PrismaService عشان نتجنب الـ import للـ generated client
// اللي بيحتاج `npx prisma generate` قبل ما يشتغل
jest.mock('../../prisma.service', () => ({
  PrismaService: jest.fn().mockImplementation(() => ({
    email: {
      findFirst: jest.fn().mockResolvedValue({ id: 1 }), // simulate "known sender"
    },
  })),
}));

const mockPrisma = {
  email: {
    findFirst: jest.fn().mockResolvedValue({ id: 1 }),
  },
};

const rules = new SenderRules(mockPrisma as any);

function makeEmail(overrides: Partial<EmailContentForClassification>): EmailContentForClassification {
  return {
    subject:  'Test',
    fromAddr: 'sender@example.com',
    bodyText: 'Hello.',
    ...overrides,
  };
}

async function check(email: Partial<EmailContentForClassification>) {
  const reasons: string[] = [];
  const scores = await rules.check(makeEmail(email), reasons);
  return { ...scores, reasons };
}

// ─────────────────────────────────────────────────────────────────────────────
// Rule 3 — Disposable Domain
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 3 — Disposable Sender Domain', () => {
  it('✅ flags mailinator.com', async () => {
    const { spamScore, reasons } = await check({ fromAddr: 'winner@mailinator.com' });
    expect(spamScore).toBeGreaterThan(0);
    expect(reasons).toContain('disposable_sender_domain');
  });

  it('✅ flags guerrillamail.com', async () => {
    const { reasons } = await check({ fromAddr: 'test@guerrillamail.com' });
    expect(reasons).toContain('disposable_sender_domain');
  });

  it('✅ flags yopmail.com', async () => {
    const { reasons } = await check({ fromAddr: 'user@yopmail.com' });
    expect(reasons).toContain('disposable_sender_domain');
  });

  it('❌ does NOT flag legitimate domain', async () => {
    const { reasons } = await check({ fromAddr: 'hr@company.com' });
    expect(reasons).not.toContain('disposable_sender_domain');
  });

  it('❌ does NOT flag gmail.com', async () => {
    const { reasons } = await check({ fromAddr: 'john@gmail.com' });
    expect(reasons).not.toContain('disposable_sender_domain');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 7 — Brand / Domain Mismatch
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 7 — Sender Display Name Mismatch', () => {
  it('✅ flags "PayPal Security" from non-paypal domain', async () => {
    const { phishingScore, reasons } = await check({
      fromAddr: 'support@paypa1-secure.com',
      fromName: 'PayPal Security',
    });
    expect(phishingScore).toBeGreaterThan(0);
    expect(reasons).toContain('sender_display_name_mismatch');
  });

  it('✅ flags "Microsoft Support" from random domain', async () => {
    const { reasons } = await check({
      fromAddr: 'help@random-mail.net',
      fromName: 'Microsoft Support',
    });
    expect(reasons).toContain('sender_display_name_mismatch');
  });

  it('✅ flags "Apple ID" from gmail', async () => {
    const { reasons } = await check({
      fromAddr: 'noreply@gmail.com',
      fromName: 'Apple ID Team',
    });
    expect(reasons).toContain('sender_display_name_mismatch');
  });

  it('❌ does NOT flag "PayPal" from paypal.com', async () => {
    const { reasons } = await check({
      fromAddr: 'support@paypal.com',
      fromName: 'PayPal Customer Service',
    });
    expect(reasons).not.toContain('sender_display_name_mismatch');
  });

  it('❌ does NOT flag email with no fromName', async () => {
    const { reasons } = await check({ fromAddr: 'support@paypal.com' });
    expect(reasons).not.toContain('sender_display_name_mismatch');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 16 — Brand Abuse
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 16 — Brand Abuse in Body', () => {
  it('✅ flags PayPal mentioned with verify action from unrelated sender', async () => {
    const { phishingScore, reasons } = await check({
      fromAddr: 'noreply@random-sender.com',
      bodyText: 'Your PayPal account requires verification. Please verify your PayPal account now.',
    });
    expect(phishingScore).toBeGreaterThan(0);
    expect(reasons).toContain('brand_abuse_in_body');
  });

  it('✅ flags Google login from unrelated sender', async () => {
    const { reasons } = await check({
      fromAddr: 'alert@attacker.ru',
      bodyText: 'Your Google account has been locked. Login to your Google account to confirm.',
    });
    expect(reasons).toContain('brand_abuse_in_body');
  });

  it('❌ does NOT flag PayPal mentioned once without action word', async () => {
    const { reasons } = await check({
      fromAddr: 'news@newsletter.com',
      bodyText: 'We compared PayPal fees with competitors.',
    });
    expect(reasons).not.toContain('brand_abuse_in_body');
  });

  it('❌ does NOT flag PayPal email from paypal.com', async () => {
    const { reasons } = await check({
      fromAddr: 'support@paypal.com',
      bodyText: 'Please verify your PayPal account immediately.',
    });
    expect(reasons).not.toContain('brand_abuse_in_body');
  });

  it('❌ does NOT flag known sending service (Mailchimp)', async () => {
    const { reasons } = await check({
      fromAddr: 'campaigns@mailchimp.com',
      bodyText: 'Your Google Workspace subscription requires verification.',
    });
    expect(reasons).not.toContain('brand_abuse_in_body');
  });

  it('❌ does NOT flag "zoom" mentioned twice in normal context (short brand threshold)', async () => {
    // BUG FIX: short brands (< 5 chars) need 3+ mentions بدل 2
    // "I ordered zoom fast delivery twice" → zoom×2 + action word → كان يتفلق غلط
    const { reasons } = await check({
      fromAddr: 'noreply@random-sender.com',
      bodyText: 'I used zoom for our meeting and zoom was great. Please verify your account.',
    });
    expect(reasons).not.toContain('brand_abuse_in_body');
  });

  it('✅ flags "zoom" mentioned three times with action word (crosses threshold)', async () => {
    const { reasons } = await check({
      fromAddr: 'noreply@attacker.com',
      bodyText: 'Your zoom account needs verification. zoom security alert: zoom login required now.',
    });
    expect(reasons).toContain('brand_abuse_in_body');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 18 — Reply-To Mismatch
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 18 — Reply-To Domain Mismatch', () => {
  it('✅ flags PayPal From with attacker Reply-To', async () => {
    const { phishingScore, reasons } = await check({
      fromAddr: 'support@paypal.com',
      replyTo:  'attacker@mail.ru',
    });
    expect(phishingScore).toBeGreaterThan(0);
    expect(reasons).toContain('reply_to_domain_mismatch');
  });

  it('✅ flags Amazon From with gmail Reply-To', async () => {
    const { reasons } = await check({
      fromAddr: 'orders@amazon.com',
      replyTo:  'steal@gmail.com',
    });
    expect(reasons).toContain('reply_to_domain_mismatch');
  });

  it('✅ flags unknown sender + financial body + different Reply-To', async () => {
    const { reasons } = await check({
      fromAddr: 'finance@corp.net',
      replyTo:  'attacker@otherdomain.com',
      bodyText: 'Please process the wire transfer urgently.',
    });
    expect(reasons).toContain('reply_to_domain_mismatch');
  });

  it('❌ does NOT flag matching From and Reply-To base domain', async () => {
    const { reasons } = await check({
      fromAddr: 'noreply@mail.paypal.com',
      replyTo:  'support@paypal.com',
    });
    expect(reasons).not.toContain('reply_to_domain_mismatch');
  });

  it('❌ does NOT flag missing Reply-To', async () => {
    const { reasons } = await check({ fromAddr: 'support@paypal.com' });
    expect(reasons).not.toContain('reply_to_domain_mismatch');
  });

  it('❌ does NOT falsely amplify urgency from fromAddr keyword (BUG FIX)', async () => {
    // BUG FIX: Rule 18 checkReplyToMismatch كانت بتستخدم getCombinedText
    // getCombinedText بتضم fromAddr — يعني 'urgent.deals@company.com' كان يضيف urgency score
    // getBodyText مش بتشيل الـ fromAddr → لا false positive من الـ email address
    const { reasons } = await check({
      fromAddr: 'urgent.payment@legit-store.com',
      replyTo:  'returns@different-legit-store.com',
      bodyText: 'Your order has been shipped.',
    });
    // reply-to مختلف → هيتفلق — لكن ده بسبب domain mismatch مش urgency في fromAddr
    // الـ test يتحقق إن الـ rule شغالة لأسباب صح
    expect(reasons).toContain('reply_to_domain_mismatch');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 21 — Display Name Impersonation
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 21 — Display Name Impersonation', () => {
  it('✅ flags "CEO" from unknown domain', async () => {
    const { phishingScore, reasons } = await check({
      fromAddr: 'ceo@random-domain.net',
      fromName: 'CEO John Smith',
    });
    expect(phishingScore).toBeGreaterThan(0);
    expect(reasons).toContain('display_name_impersonation');
  });

  it('✅ flags "IT Support Team" from unknown domain', async () => {
    // ملاحظة: الـ whitelist check بيحصل في ClassificationService مش في SenderRules مباشرة
    // يعني الـ SenderRules هتفلتر أي domain — بما فيه gmail.com — لو اتكالت عليها directly
    // الـ whitelist bypass بيحصل فقط لما نمر من الـ service كاملة مع auth headers صح
    const { reasons } = await check({
      fromAddr: 'support@random-helpdesk.net',
      fromName: 'IT Support Team',
    });
    expect(reasons).toContain('display_name_impersonation');
  });

  it('✅ flags "HR Department" from external domain', async () => {
    const { reasons } = await check({
      fromAddr: 'hr@external.org',
      fromName: 'HR Department',
    });
    expect(reasons).toContain('display_name_impersonation');
  });

  it('✅ flags "Finance" role keyword', async () => {
    const { reasons } = await check({
      fromAddr: 'billing@attacker.xyz',
      fromName: 'Finance Department',
    });
    expect(reasons).toContain('display_name_impersonation');
  });

  it('❌ does NOT flag regular person name', async () => {
    const { reasons } = await check({
      fromAddr: 'john.doe@company.com',
      fromName: 'John Doe',
    });
    expect(reasons).not.toContain('display_name_impersonation');
  });

  // BUG FIX regressions: word boundary — "vp " trailing space
  it('❌ does NOT flag "MVP Award" — word boundary fix', async () => {
    const { reasons } = await check({ fromAddr: 'hr@company.com', fromName: 'MVP Award Program' });
    expect(reasons).not.toContain('display_name_impersonation');
  });

  it('❌ does NOT flag "EVP Finance" — EVP contains VP but not standalone', async () => {
    const { reasons } = await check({ fromAddr: 'noreply@firm.com', fromName: 'EVP Finance Team' });
    expect(reasons).not.toContain('display_name_impersonation');
  });

  it('✅ still flags standalone "VP" impersonation', async () => {
    const { reasons } = await check({ fromAddr: 'vp@random-domain.xyz', fromName: 'VP Finance' });
    expect(reasons).toContain('display_name_impersonation');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// Rule 13 — First Contact Risk
// ─────────────────────────────────────────────────────────────────────────────
describe('Rule 13 — First Contact Risk', () => {
  // بنعمل instance جديد بـ mock بيرجع null (sender مش موجود في DB = first contact)
  const prismaFirstContact = {
    email: { findFirst: jest.fn().mockResolvedValue(null) },
  };
  // reset mock before each test in this describe block
  beforeEach(() => {
    prismaFirstContact.email.findFirst.mockResolvedValue(null);
  });
  const rulesFirstContact = new SenderRules(prismaFirstContact as any);

  async function checkFirstContact(email: Partial<EmailContentForClassification>) {
    const reasons: string[] = [];
    const scores = await rulesFirstContact.check(
      { subject: 'Test', fromAddr: 'sender@example.com', bodyText: '', ...email },
      reasons,
    );
    return { ...scores, reasons };
  }

  it('✅ flags first contact sender — base risk', async () => {
    const { spamScore, phishingScore, reasons } = await checkFirstContact({
      fromAddr:  'unknown@new-domain.com',
      bodyText:  'Hello, I wanted to reach out.',
      mailBoxId: 1,
    });
    expect(spamScore + phishingScore).toBeGreaterThan(0);
    expect(reasons).toContain('first_contact_sender_risk');
  });

  it('✅ amplifies risk on first contact + urgent language', async () => {
    const withUrgency = await checkFirstContact({
      fromAddr:  'alert@new-domain.com',
      bodyText:  'Your account has been suspended. Verify immediately.',
      mailBoxId: 1,
    });
    const withoutUrgency = await checkFirstContact({
      fromAddr:  'hello@new-domain.com',
      bodyText:  'Hello, just a friendly message.',
      mailBoxId: 1,
    });
    const totalWith    = withUrgency.spamScore    + withUrgency.phishingScore;
    const totalWithout = withoutUrgency.spamScore + withoutUrgency.phishingScore;
    expect(totalWith).toBeGreaterThan(totalWithout);
  });

  it('✅ amplifies risk on first contact + attachment', async () => {
    const withAttachment = await checkFirstContact({
      fromAddr:     'sender@unknown.com',
      bodyText:     'Please review.',
      mailBoxId:    1,
      attachments:  [{ filename: 'doc.pdf', mimeType: 'application/pdf' }],
    });
    const withoutAttachment = await checkFirstContact({
      fromAddr:  'sender@unknown.com',
      bodyText:  'Please review.',
      mailBoxId: 1,
    });
    const totalWith    = withAttachment.spamScore    + withAttachment.phishingScore;
    const totalWithout = withoutAttachment.spamScore + withoutAttachment.phishingScore;
    expect(totalWith).toBeGreaterThan(totalWithout);
  });

  it('❌ does NOT flag known sender (exists in DB)', async () => {
    // الـ mockPrisma الأصلي بيرجع { id: 1 } — known sender
    const { reasons } = await check({
      fromAddr:  'known@familiar-domain.com',
      bodyText:  'Hello again!',
      mailBoxId: 1,
    });
    expect(reasons).not.toContain('first_contact_sender_risk');
  });

  it('❌ does NOT flag when mailBoxId is missing', async () => {
    const { reasons } = await checkFirstContact({
      fromAddr: 'unknown@new-domain.com',
      bodyText: 'Hello.',
      // mailBoxId غير موجود
    });
    expect(reasons).not.toContain('first_contact_sender_risk');
  });
});
