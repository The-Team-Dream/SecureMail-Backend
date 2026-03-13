// ─────────────────────────────────────────────────────────────────────────────
// detection/rules/content/content-detection.rules.ts
//
// Content-category rules as DetectionRule plugins.
//
// Rules:
//   UrgentPhishingLanguageRule        (Rule 8)
//   BECLanguageRule                   (Rule 14)
//   CredentialHarvestingRule          (Rule 22)
//   ExcessiveCapitalizationRule       (Rule 4)
//   ExcessiveExclamationRule          (Rule 5)
//   RiskyAttachmentRule               (Rule 15)
// ─────────────────────────────────────────────────────────────────────────────

import { BaseDetectionRule, RuleResult } from '../detection-rule.interface';
import { DetectionContext } from '../../rule-engine/detection-context';

const PHISHING_URGENT_PATTERNS = [
  /\b(account\s+(suspended|locked|disabled|compromised))\b/i,
  /\b(verify\s+(your|now|immediately))\b/i,
  /\b(confirm\s+(your|now))\b/i,
  /\b(urgent|immediate|asap|act now)\b/i,
  /\b(security\s+alert|suspicious\s+activity)\b/i,
  /\b(password\s+expired|reset\s+password)\b/i,
  /\b(update\s+your\s+information)\b/i,
  /\b(click\s+here\s+to\s+(verify|confirm|update))\b/i,
  /\b(unauthorized\s+access|someone\s+tried)\b/i,
  /\b(limited\s+time|expires\s+soon|within\s+\d+\s*hours?)\b/i,
  /(حسابك\s+(معلق|مغلق|موقوف))/u,
  /(نشاط\s+مشبوه)/u,
];

const BEC_PATTERNS = [
  /\b(urgent\s+payment|wire\s+transfer|bank\s+transfer)\b/i,
  /\b(gift\s+card[s]?|itunes|google\s+play\s+card)\b/i,
  /\b(confidential\s+(request|matter))\b/i,
  /\b(handle\s+this\s+(quickly|immediately|urgently))\b/i,
  /\b(don['`]?t\s+(tell|mention|discuss)\s+(anyone|others))\b/i,
  /\b(keep\s+this\s+(private|confidential|between\s+us))\b/i,
  /\b(ceo|president|director|executive)\s+(request|approval|authorization)\b/i,
  /\b(process\s+this\s+payment|approve\s+this\s+transfer)\b/i,
];

const RISKY_EXTENSIONS = [
  '.exe', '.bat', '.cmd', '.scr', '.pif', '.vbs', '.js', '.jse',
  '.wsf', '.msi', '.jar', '.ps1', '.hta', '.reg', '.xlsm', '.docm',
];

const ARCHIVE_EXTENSIONS = new Set(['.zip', '.rar', '.7z', '.gz', '.tar', '.iso']);

// ─── Rule 8: Urgent Phishing Language ─────────────────────────────────────────
export class UrgentPhishingLanguageRule extends BaseDetectionRule {
  readonly id          = 'urgent_phishing_language';
  readonly description = 'Email contains urgency or threatening language typical of phishing';
  readonly category    = 'content' as const;
  readonly severity    = 3 as const;
  readonly weight      = 10;
  readonly scoreTarget = 'phishing' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const text = ctx.parsedEmail.bodyPlain;
    const matchedPattern = PHISHING_URGENT_PATTERNS.find(p => p.test(text));
    if (!matchedPattern) return this.notTriggered();
    return this.triggered(
      `Urgent/threatening phishing language detected: matches pattern "${matchedPattern.source.slice(0, 40)}…"`,
    );
  }
}

// ─── Rule 14: BEC Language ────────────────────────────────────────────────────
export class BECLanguageRule extends BaseDetectionRule {
  readonly id          = 'bec_language_detected';
  readonly description = 'Business Email Compromise patterns: financial requests, secrecy instructions';
  readonly category    = 'content' as const;
  readonly severity    = 4 as const;
  readonly weight      = 25;
  readonly scoreTarget = 'phishing' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const text   = ctx.parsedEmail.bodyPlain;
    const hits   = BEC_PATTERNS.filter(p => p.test(text));
    if (hits.length === 0) return this.notTriggered();

    const score = Math.min(hits.length * 10, 25);
    return this.triggered(
      `BEC language patterns found (${hits.length} match${hits.length > 1 ? 'es' : ''}): ` +
      hits.slice(0, 2).map(p => p.source.slice(0, 30)).join('; '),
      score,
    );
  }
}

// ─── Rule 22: Credential Harvesting ──────────────────────────────────────────
export class CredentialHarvestingRule extends BaseDetectionRule {
  readonly id          = 'credential_harvesting_attempt';
  readonly description = 'HTML body contains login forms or password inputs pointing to external domains';
  readonly category    = 'content' as const;
  readonly severity    = 5 as const;
  readonly weight      = 50;
  readonly scoreTarget = 'phishing' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const html = ctx.parsedEmail.bodyHtml ?? '';
    if (!html) return this.notTriggered();

    const hasPasswordInput = /<input[^>]+type\s*=\s*['"]?password['"]?/i.test(html);
    let score = 0;

    if (hasPasswordInput) {
      score += 40;
      // Check if form action is external
      const formMatch = /<form[^>]+action\s*=\s*['"]?(https?:\/\/[^'">\s]+)/gi.exec(html);
      if (formMatch) {
        score += 30;
      }
    } else if (/<form[\s>]/i.test(html)) {
      score += 5; // bare form = mild signal only
    }

    if (score === 0) return this.notTriggered();

    return this.triggered(
      `HTML body contains ${hasPasswordInput ? 'password input field' : 'form'} pointing to external URL. ` +
      'This is a credential harvesting indicator.',
      Math.min(score, 50),
    );
  }
}

// ─── Rule 4: Excessive Capitalization ────────────────────────────────────────
export class ExcessiveCapitalizationRule extends BaseDetectionRule {
  readonly id          = 'excessive_capitalization';
  readonly description = 'Subject or body has more than 50% uppercase characters — spam indicator';
  readonly category    = 'content' as const;
  readonly severity    = 2 as const;
  readonly weight      = 10;
  readonly scoreTarget = 'spam' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const text = `${ctx.parsedEmail.subject} ${ctx.parsedEmail.bodyPlain}`;
    const capsRatio = (text.match(/[A-Z]/g)?.length ?? 0) / Math.max(text.length, 1);
    if (capsRatio <= 0.5) return this.notTriggered();
    return this.triggered(`${Math.round(capsRatio * 100)}% of characters are uppercase (threshold: 50%)`);
  }
}

// ─── Rule 5: Excessive Exclamation Marks ─────────────────────────────────────
export class ExcessiveExclamationRule extends BaseDetectionRule {
  readonly id          = 'excessive_exclamation_marks';
  readonly description = 'More than 3 exclamation marks in email body — spam indicator';
  readonly category    = 'content' as const;
  readonly severity    = 1 as const;
  readonly weight      = 5;
  readonly scoreTarget = 'spam' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const count = (ctx.parsedEmail.bodyPlain.match(/!/g) || []).length;
    if (count <= 3) return this.notTriggered();
    return this.triggered(`${count} exclamation marks found (threshold: 3)`);
  }
}

// ─── Rule 15: Risky Attachment ────────────────────────────────────────────────
export class RiskyAttachmentRule extends BaseDetectionRule {
  readonly id          = 'risky_attachment_detected';
  readonly description = 'Email contains executable, script, or high-risk file type';
  readonly category    = 'attachment' as const;
  readonly severity    = 4 as const;
  readonly weight      = 20;
  readonly scoreTarget = 'phishing' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    if (!ctx.parsedEmail.hasAttachment) return this.notTriggered();

    let score = 0;
    const flagged: string[] = [];
    const hasPhishContext = PHISHING_URGENT_PATTERNS.some(p => p.test(ctx.parsedEmail.bodyPlain));

    for (const att of ctx.parsedEmail.attachments) {
      const ext = att.filename.substring(att.filename.lastIndexOf('.')).toLowerCase();

      if (RISKY_EXTENSIONS.includes(ext)) {
        score += 20;
        if (hasPhishContext) score += 10;
        flagged.push(`${att.filename} (${ext})`);
      } else if (ARCHIVE_EXTENSIONS.has(ext)) {
        score += hasPhishContext ? 15 : 10;
        flagged.push(`${att.filename} (archive)`);
      }
    }

    if (score === 0) return this.notTriggered();

    return this.triggered(
      `Risky attachment(s): ${flagged.slice(0, 3).join(', ')}${hasPhishContext ? ' (combined with phishing context)' : ''}`,
      Math.min(score, 30),
    );
  }
}
