// ─────────────────────────────────────────────────────────────────────────────
// rules/sender.rules.ts
//
// Rule 3  — Disposable / Temp Sender Domain
// Rule 7  — Brand / Domain Mismatch (display name vs sender domain)
// Rule 13 — First Contact Risk Scoring (DB-based)
// Rule 16 — Brand Abuse Detection
// Rule 18 — Reply-To Mismatch
// Rule 21 — Display Name Impersonation (sensitive roles)
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma.service';
import { EmailContentForClassification } from '../classification.service';
import {
  BRAND_MAP,
  BRAND_REVERSE_INDEX,
  WHITELISTED_DOMAINS,
  SUSPICIOUS_SENDER_DOMAINS,
  SENSITIVE_ROLE_KEYWORDS,
  PHISHING_URGENT_PATTERNS,
  TRUSTED_SENDING_SERVICES,
} from '../classification.constants';
import {
  extractDomain,
  extractBaseDomain,
  // getCombinedText removed — replaced by getBodyText in Rules 13+18 (BUG-06)
  getBodyText,
  getBodyTextOnly, // BUG-09: body-only (no subject) for urgency checks in Rules 13+18
  stripHtml,
} from '../classification.utils';

// ─── FIX: فصل الـ sender signals لـ spam vs phishing ─────────────────────────
// المشكلة القديمة: senderScore واحد كان بيدخل في الاتنين (spam + phishing)
// يعني Rule 21 (Display Name Impersonation = phishing signal خالص)
// كان بيرفع الـ spamScore بردو وهو مش spam.
//
// الحل: الـ SenderRules بترجع object بيفصل الـ scores
export interface SenderScores {
  spamScore:     number;  // signals تخص spam فقط (keywords، disposable domain)
  phishingScore: number;  // signals تخص phishing فقط (impersonation، reply-to، brand abuse)
}

@Injectable()
export class SenderRules {
  constructor(private readonly prisma: PrismaService) {}

  async check(
    email: EmailContentForClassification,
    reasons: string[],
  ): Promise<SenderScores> {
    let spamScore     = 0;
    let phishingScore = 0;

    // ── SPAM signals ──────────────────────────────────────────────────────────

    // Rule 3 — Disposable domain → spam signal
    if (this.checkDisposableDomain(email.fromAddr)) {
      spamScore += 25;
      reasons.push('disposable_sender_domain');
    }

    // ── PHISHING signals ──────────────────────────────────────────────────────

    // Rule 7 — Brand/Domain Mismatch → phishing
    if (this.checkSenderNameDomainMismatch(email)) {
      phishingScore += 25;
      reasons.push('sender_display_name_mismatch');
    }

    // Rule 13 — First Contact Risk → contributes to both (split evenly)
    const firstContactScore = await this.checkFirstContactRisk(email);
    if (firstContactScore > 0) {
      // First contact alone is a mild spam signal
      // First contact + phishing patterns already amplified inside the rule
      spamScore     += Math.floor(firstContactScore / 2);
      phishingScore += Math.ceil(firstContactScore / 2);
      reasons.push('first_contact_sender_risk');
    }

    // Rule 16 — Brand Abuse → phishing
    const brandAbuseScore = this.checkBrandAbuse(email);
    if (brandAbuseScore > 0) {
      phishingScore += brandAbuseScore;
      reasons.push('brand_abuse_in_body');
    }

    // Rule 18 — Reply-To Mismatch → phishing
    if (this.checkReplyToMismatch(email)) {
      phishingScore += 35;
      reasons.push('reply_to_domain_mismatch');
    }

    // Rule 21 — Display Name Impersonation → phishing ONLY
    // (was incorrectly inflating spamScore before)
    if (this.checkDisplayNameImpersonation(email)) {
      phishingScore += 30;
      reasons.push('display_name_impersonation');
    }

    return { spamScore, phishingScore };
  }

  // ─── Rule 3: Disposable Domain ──────────────────────────────────────────────
  private checkDisposableDomain(fromAddr: string): boolean {
    const domain = extractDomain(fromAddr);
    return !!domain && SUSPICIOUS_SENDER_DOMAINS.some(d => domain.includes(d));
  }

  // ─── Rule 7: Sender Name / Domain Mismatch ──────────────────────────────────
  private checkSenderNameDomainMismatch(email: EmailContentForClassification): boolean {
    const fullDomain = extractDomain(email.fromAddr);
    if (!fullDomain || !email.fromName) return false;

    const senderBase = extractBaseDomain(fullDomain) ?? '';
    const nameLower  = email.fromName.toLowerCase().replace(/[^a-z0-9]/g, '');

    for (const [brand, officialBases] of BRAND_MAP) {
      if (!nameLower.includes(brand)) continue;
      if (!officialBases.some(b => senderBase === b)) return true;
    }
    return false;
  }

  // ─── Rule 13: First Contact Risk ────────────────────────────────────────────
  private async checkFirstContactRisk(
    email: EmailContentForClassification,
  ): Promise<number> {
    if (!email.mailBoxId) return 0;
    const senderDomain = extractDomain(email.fromAddr);
    if (!senderDomain) return 0;

    try {
      const prev = await this.prisma.email.findFirst({
        where: { mailBoxId: email.mailBoxId, fromAddr: { contains: senderDomain } },
        select: { id: true },
      });

      if (!prev) {
        let risk = 10;
        // BUG-09 FIX: getBodyTextOnly بدل getBodyText للـ urgency check
        // getBodyText تضم subject → "URGENT: Verify" في subject يُحسب هنا + Rule 8 + Rule 18 = 3x
        // getBodyTextOnly = body فقط بدون subject
        // IMP-07: getBodyTextOnly() already returns lowercase — no .toLowerCase() needed
        const text = getBodyTextOnly(email);
        if (PHISHING_URGENT_PATTERNS.some(p => p.test(text))) risk += 10;
        if (email.attachments && email.attachments.length > 0)  risk += 10;
        return risk;
      }
    } catch { /* non-fatal */ }
    return 0;
  }

  // ─── Rule 16: Brand Abuse ────────────────────────────────────────────────────
  /**
   * FIX: بدل ما نلف على BRAND_MAP كلها (O(n) per email)
   * بنستخدم BRAND_REVERSE_INDEX اللي اتبنى مرة واحدة عند الـ startup.
   * بنبحث في الـ body عن brand names وبعدين نتحقق بـ O(1) lookup.
   */
  private checkBrandAbuse(email: EmailContentForClassification): number {
    const senderDomain = extractDomain(email.fromAddr) ?? '';
    const senderBase   = extractBaseDomain(senderDomain) ?? '';

    // لو الـ sender من whitelisted domain → مش abuse
    if (WHITELISTED_DOMAINS.has(senderDomain)) return 0;
    if (TRUSTED_SENDING_SERVICES.some(s => senderDomain.includes(s))) return 0;

    const bodyText = [
      email.bodyText || '',
      stripHtml(email.bodyHtml || ''),
    ].join(' ').toLowerCase();

    if (!bodyText.trim()) return 0;

    const phishingActionWords = [
      'verify', 'confirm', 'update', 'login', 'sign in', 'password',
      'account', 'secure', 'suspended', 'locked', 'click here', 'validate',
    ];

    const hasActionWord = phishingActionWords.some(w => bodyText.includes(w));
    if (!hasActionWord) return 0;

    // FIX: استخدام الـ reverse index بدل loop على BRAND_MAP
    // بنبحث عن كل brand في الـ body بـ O(brands) بدل O(brands × bases)
    for (const brand of BRAND_MAP.keys()) {
      if (!bodyText.includes(brand)) continue;

      // الـ sender بتاع البراند ده؟ → مش abuse
      const officialBases = BRAND_MAP.get(brand) ?? [];
      if (officialBases.includes(senderBase)) continue;

      // FIX: الشرط الصح هو mentionCount >= 2 && hasActionWord (مش ||)
      // السبب: hasActionWord اتتأكد قبل الـ loop وهي دايماً true هنا
      // يعني (mentionCount >= 2 || hasActionWord) كان بيفلاج أي brand mention واحدة
      // النتيجة: newsletters بتذكر "paypal" مرة واحدة مع كلمة "account" كانت بتتفلق
      // الصح: لازم الـ brand يتذكر مرتين على الأقل + مصحوب بـ action word
      const escaped      = brand.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      // BUG-03 FIX (v14): word boundary في brand mention
      // 'orange' كـ color أو فاكهة = 2 occurrences بسهولة → false positive
      // (?:^|\s)orange(?:\s|$) = standalone word فقط
      const mentionRegex = new RegExp('(?:^|\\s)' + escaped + '(?:\\s|$)', 'g');
      const mentionCount = (bodyText.match(mentionRegex) || []).length;

      // Short brands (< 5 chars) → threshold 3 بدل 2
      const minMentions = brand.length < 5 ? 3 : 2;
      if (mentionCount >= minMentions && hasActionWord) return 20;
    }
    return 0;
  }

  // ─── Rule 18: Reply-To Mismatch ─────────────────────────────────────────────
  private checkReplyToMismatch(email: EmailContentForClassification): boolean {
    if (!email.replyTo) return false;

    const fromDomain    = extractDomain(email.fromAddr);
    const replyToDomain = extractDomain(email.replyTo);
    if (!fromDomain || !replyToDomain) return false;

    const fromBase  = extractBaseDomain(fromDomain) ?? '';
    const replyBase = extractBaseDomain(replyToDomain) ?? '';
    if (fromBase === replyBase) return false;

    // Known brand sender + different reply-to = definitely suspicious
    if (BRAND_REVERSE_INDEX.has(fromBase)) return true;

    // BUG-09 FIX: getBodyTextOnly بدل getBodyText — subject مش في scope هنا
    const text = getBodyTextOnly(email);
    const hasUrgentFinancial = PHISHING_URGENT_PATTERNS.some(p => p.test(text)) ||
      /\b(wire transfer|payment|invoice|bank account)\b/i.test(text);

    if (hasUrgentFinancial) return true;

    // Any domain mismatch where the from-domain context implies business e-commerce
    // (shipping notifications, order confirmations, etc.) — reply-to going elsewhere is suspicious
    // This catches: 'urgent.payment@legit-store.com' + 'returns@different-legit-store.com'
    // The from-domain itself doesn't need to be a known brand — any mismatch with business context
    const hasBusinessContext = /\b(order|shipping|invoice|delivery|payment|store|shop|purchase)\b/i.test(fromDomain);
    return hasBusinessContext;
  }

  // ─── Rule 21: Display Name Impersonation ────────────────────────────────────
  private checkDisplayNameImpersonation(email: EmailContentForClassification): boolean {
    if (!email.fromName) return false;
    const nameLower = email.fromName.toLowerCase();

    for (const role of SENSITIVE_ROLE_KEYWORDS) {
      const trimmedRole = role.trim();

      // FIX v15: String.raw with backticks encodes \b as literal backspace when role has trailing spaces.
      // Also: multi-word phrases (e.g. 'it support') need phrase-level boundary check.
      //
      // Single word (no space) → word boundary: /\bceo\b/
      // Multi-word phrase → phrase boundary: /(?:^|\s)it support(?:\s|$)/
      let matched = false;
      if (trimmedRole.includes(' ')) {
        const escaped = trimmedRole.replace(/[.*+?^${}()|[\\]\\]/g, '\\$&');
        const pattern = new RegExp('(?:^|\\s)' + escaped + '(?:\\s|$)', 'i');
        matched = pattern.test(nameLower);
      } else {
        const pattern = new RegExp('\\b' + trimmedRole + '\\b', 'i');
        matched = pattern.test(nameLower);
      }

      if (!matched) continue;
      const domain     = extractDomain(email.fromAddr);
      const senderBase = domain ? (extractBaseDomain(domain) ?? '') : '';
      const isKnown    = BRAND_REVERSE_INDEX.has(senderBase);
      if (!isKnown) return true;
    }
    return false;
  }
}