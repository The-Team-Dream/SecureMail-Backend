// ─────────────────────────────────────────────────────────────────────────────
// rules/content.rules.ts
//
// Rule 1+2 — Spam Keywords + Fuzzy Match
// Rule 4   — Excessive CAPS
// Rule 5   — Excessive Exclamation Marks
// Rule 6   — Excessive Links
// Rule 8   — Urgent / Threatening Language
// Rule 14  — BEC Language Detection
// Rule 15  — Attachment Risk Context
// Rule 22  — HTML Credential Harvesting
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable } from '@nestjs/common';
import { EmailContentForClassification } from '../classification.service';
import {
  PHISHING_URGENT_PATTERNS,
  BEC_PATTERNS,
  RISKY_ATTACHMENT_EXTENSIONS,
  FINANCIAL_ATTACHMENT_KEYWORDS,
  BRAND_MAP,
  BRAND_REVERSE_INDEX,
  WHITELISTED_DOMAINS,
  TRUSTED_SENDING_SERVICES,
} from '../classification.constants';
import {
  stripHtml,
  getBodyText,
  extractDomain,
  extractBaseDomain,
  extractDomainFromUrl,
  countSpamKeywordHits,
  isIpUrl,
} from '../classification.utils';

@Injectable()
export class ContentRules {

  check(email: EmailContentForClassification, reasons: string[]): { spamScore: number; phishingScore: number } {
    let score = 0;

    // FIX: الـ spam keywords بتشتغل على الـ body بس — مش getCombinedText
    // FIX: استخدام getBodyText() من utils بدل الـ manual construction
    // السبب: getCombinedText كانت تضم الـ fromAddr والـ fromName
    // يعني domain فيه كلمة "work" أو "free" كان بيدي false positive
    const bodyOnly = getBodyText(email);

    // Rule 1+2 — Spam Keywords + Fuzzy Match
    const keywordHits = countSpamKeywordHits(bodyOnly);
    if (keywordHits > 0) {
      score += keywordHits * 8;
      reasons.push('spam_keywords_detected');
    }

    // Rule 4 — Excessive CAPS (على الـ subject والـ body بس)
    const capsText  = `${email.subject || ''} ${email.bodyText || ''}`;
    const capsRatio = (capsText.match(/[A-Z]/g)?.length ?? 0) / Math.max(capsText.length, 1);
    if (capsRatio > 0.5) {
      score += 10;
      reasons.push('excessive_capitalization');
    }

    // Rule 5 — Excessive exclamation marks
    if ((bodyOnly.match(/!/g) || []).length > 3) {
      score += 5;
      reasons.push('excessive_exclamation_marks');
    }

    // Rule 6 — Excessive links
    if (this.checkExcessiveLinks(email)) {
      score += 10;
      reasons.push('excessive_links');
    }

    // Rule 8 — Urgent language
    for (const pattern of PHISHING_URGENT_PATTERNS) {
      if (pattern.test(bodyOnly)) {
        score += 10;
        reasons.push('urgent_phishing_language');
        break;
      }
    }

    // Rule 14 — BEC Language
    const becScore = this.checkBECLanguage(email, bodyOnly);
    if (becScore > 0) {
      score += becScore;
      reasons.push('bec_language_detected');
    }

    // Rule 15 — Attachment Risk
    const attachScore = this.checkAttachmentRisk(email, bodyOnly);
    if (attachScore > 0) {
      score += attachScore;
      reasons.push('risky_attachment_detected');
    }

    // Rule 22 — HTML Credential Harvesting
    // FIX: credScore يروح لـ phishingScore — credential harvesting هو phishing attack بالتعريف
    // ContentRules.check() بترجع { spamScore, phishingScore } بدل رقم واحد
    const credScore = this.checkCredentialHarvesting(email);
    if (credScore > 0) {
      reasons.push('credential_harvesting_attempt');
    }

    return { spamScore: score, phishingScore: credScore };
  }

  // ─── Rule 6: Excessive Links ────────────────────────────────────────────────
  private checkExcessiveLinks(email: EmailContentForClassification): boolean {
    const links = (email.bodyHtml || '').match(/href=['"](.*?)['"]/gi) || [];
    return links.length > 5;
  }

  // ─── Rule 14: BEC Language ───────────────────────────────────────────────────
  private checkBECLanguage(
    email: EmailContentForClassification,
    bodyOnly: string,
  ): number {
    const matchCount = BEC_PATTERNS.filter(p => p.test(bodyOnly)).length;
    if (matchCount === 0) return 0;

    const domain     = extractDomain(email.fromAddr);
    const senderBase = domain ? (extractBaseDomain(domain) ?? '') : '';
    const isKnown    = BRAND_REVERSE_INDEX.has(senderBase); // FIX: O(1)
    return isKnown ? 0 : Math.min(matchCount * 10, 25);
  }

  // ─── Rule 15: Attachment Risk ────────────────────────────────────────────────
  private checkAttachmentRisk(
    email: EmailContentForClassification,
    bodyOnly: string,
  ): number {
    if (!email.attachments || email.attachments.length === 0) return 0;

    let score      = 0;
    const hasPhish = PHISHING_URGENT_PATTERNS.some(p => p.test(bodyOnly));

    // BUG-07 FIX (v14): .zip score 20 = same as .exe — too aggressive
    // .zip شائع في invoices شرعية → false positives على business emails
    // Tier system: executables (+20), archives (+10, +15 if phishing context)
    
    const ARCHIVE_EXTENSIONS = new Set(['.zip', '.rar', '.7z', '.gz', '.tar', '.iso', '.img']);

    for (const att of email.attachments) {
      const ext = att.filename.substring(att.filename.lastIndexOf('.')).toLowerCase();

      if (RISKY_ATTACHMENT_EXTENSIONS.includes(ext)) {
        if (ARCHIVE_EXTENSIONS.has(ext)) {
          // Archives: lower base score — common in legitimate invoices
          score += hasPhish ? 15 : 10;
        } else {
          // Executables/scripts: high score regardless of context
          score += 20;
          if (hasPhish) score += 10;
        }
      }

      if (['.pdf', '.doc', '.docx', '.xls', '.xlsx'].includes(ext)) {
        if (FINANCIAL_ATTACHMENT_KEYWORDS.some(k => bodyOnly.includes(k))) score += 15;
      }
    }
    return Math.min(score, 30);
  }

  // ─── Rule 22: HTML Credential Harvesting ────────────────────────────────────
  private checkCredentialHarvesting(email: EmailContentForClassification): number {
    const html = email.bodyHtml || '';
    if (!html) return 0;

    // IMP: extract hasPasswordInput once — regex was running twice on same html
    const hasPasswordInput = /<input[^>]+type\s*=\s*['"]?password['"]?/i.test(html);

    let score = 0;

    // password input في email = دايماً مشبوه بغض النظر عن الـ sender
    if (hasPasswordInput) score += 40;

    let hasWhitelistedForm = false;
    let hasExternalForm    = false;

    const formActionRegex = /<form[^>]+action\s*=\s*['"]?(https?:\/\/[^'" >]+)['"]?/gi;
    let match: RegExpExecArray | null;
    while ((match = formActionRegex.exec(html)) !== null) {
      const actionUrl    = match[1];
      const actionDomain = extractDomainFromUrl(actionUrl) ?? '';
      const actionBase   = extractBaseDomain(actionDomain) ?? '';

      const actionIsWhitelisted = WHITELISTED_DOMAINS.has(actionDomain) ||
                                  WHITELISTED_DOMAINS.has(`${actionBase}.com`) ||
                                  TRUSTED_SENDING_SERVICES.some(s => actionDomain.includes(s));

      if (actionIsWhitelisted) { hasWhitelistedForm = true; break; }

      hasExternalForm = true;
      if (hasPasswordInput) { score += 30; }           // password + external form = very suspicious
      else                  { score += 10; }           // external form alone = mild signal only

      if (isIpUrl(actionUrl)) score += 15;            // IP-based action → extra red flag
      break;
    }

    // Bare form (no external action URL) = mild signal — skip if a whitelisted form was found
    if (score === 0 && !hasWhitelistedForm && !hasExternalForm && /<form[\s>]/i.test(html)) {
      score += 5;
    }

    return Math.min(score, 50);
  }
}
