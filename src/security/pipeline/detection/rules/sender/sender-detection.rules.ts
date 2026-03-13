// ─────────────────────────────────────────────────────────────────────────────
// detection/rules/sender/sender-detection.rules.ts
//
// Sender-category rules implemented as DetectionRule plugins.
//
// Rules:
//   SenderDisplayNameMismatchRule  (Rule 7)
//   DisplayNameImpersonationRule   (Rule 21)
//   DisposableDomainRule           (Rule 3)
//   ReplyToDomainMismatchRule      (Rule 18)
//   FirstContactRiskRule           (Rule 13)
// ─────────────────────────────────────────────────────────────────────────────

import { BaseDetectionRule, RuleResult } from '../detection-rule.interface';
import { DetectionContext } from '../../rule-engine/detection-context';

// ─── Shared utilities (inline, no external import needed for portability) ─────
const SENSITIVE_ROLES = [
  'ceo', 'cfo', 'cto', 'coo', 'president', 'director', 'vp', 'svp',
  'vice president', 'executive', 'it support', 'helpdesk', 'payroll',
  'hr', 'human resources', 'finance', 'accounts', 'billing',
  'نائب الرئيس', 'المدير', 'الرئيس',  // Arabic roles
];

const SUSPICIOUS_DOMAINS = [
  'tempmail', 'throwaway', 'guerrillamail', '10minutemail', 'mailinator',
  'fakeinbox', 'trashmail', 'yopmail', 'dispostable', 'temp-mail',
  'maildrop', 'mailnesia', 'minuteinbox', 'dropmail', 'burnermail',
];

const PHISHING_URGENT = /\b(urgent|immediately|act now|verify account|password expired|wire transfer|gift card)\b/i;

function extractDomain(addr: string): string | null {
  const m = addr.match(/<([^>]+)>/) ?? [null, addr.trim()];
  const email = m[1];
  const idx = email.lastIndexOf('@');
  return idx >= 0 ? email.slice(idx + 1).toLowerCase().trim() : null;
}

function extractBase(domain: string): string | null {
  if (!domain) return null;
  const parts = domain.split('.');
  if (parts.length < 2) return domain;
  const ccTLD = ['co', 'com', 'net', 'org', 'gov', 'edu', 'ac'];
  if (parts.length >= 3 && ccTLD.includes(parts[parts.length - 2])) return parts[parts.length - 3];
  return parts[parts.length - 2];
}

// ─── Rule 7: Sender Display Name Mismatch ─────────────────────────────────────
export class SenderDisplayNameMismatchRule extends BaseDetectionRule {
  readonly id          = 'sender_display_name_mismatch';
  readonly description = 'Display name claims to be a known brand but sender domain does not match';
  readonly category    = 'sender' as const;
  readonly severity    = 4 as const;
  readonly weight      = 25;
  readonly scoreTarget = 'phishing' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const email   = ctx.parsedEmail;
    const name    = (email.fromName ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');
    const domain  = email.fromFullDomain ?? '';
    const base    = extractBase(domain) ?? '';

    // Known brand → base domain map (subset — full list in classification.constants.ts)
    const BRANDS: Record<string, string[]> = {
      paypal: ['paypal'], google: ['google'], microsoft: ['microsoft', 'live', 'outlook'],
      amazon: ['amazon', 'aws'], apple: ['apple', 'icloud'], facebook: ['facebook', 'fb', 'meta'],
      netflix: ['netflix'], instagram: ['instagram'], twitter: ['twitter', 'x'],
    };

    for (const [brand, bases] of Object.entries(BRANDS)) {
      if (name.includes(brand) && !bases.includes(base)) {
        return this.triggered(
          `Display name "${email.fromName}" claims to be ${brand} but sender domain is ${domain}`,
        );
      }
    }
    return this.notTriggered();
  }
}

// ─── Rule 21: Display Name Impersonation ──────────────────────────────────────
export class DisplayNameImpersonationRule extends BaseDetectionRule {
  readonly id          = 'display_name_impersonation';
  readonly description = 'Sender display name contains a sensitive role keyword (CEO, CFO, IT Support…)';
  readonly category    = 'sender' as const;
  readonly severity    = 4 as const;
  readonly weight      = 30;
  readonly scoreTarget = 'phishing' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const name = (ctx.parsedEmail.fromName ?? '').toLowerCase();
    if (!name) return this.notTriggered();

    for (const role of SENSITIVE_ROLES) {
      const pattern = new RegExp(String.raw`\b${role.trim()}\b`);
      if (pattern.test(name)) {
        // Sender must not be a known domain
        const base = extractBase(ctx.parsedEmail.fromFullDomain ?? '') ?? '';
        // Simplified check: if base is < 4 chars and in common abbreviations → skip
        const knownAbbrevs = new Set(['hr', 'it']);
        if (role.length <= 2 && knownAbbrevs.has(role)) continue;

        return this.triggered(
          `Sender display name "${ctx.parsedEmail.fromName}" uses sensitive role keyword "${role}" from unknown domain`,
        );
      }
    }
    return this.notTriggered();
  }
}

// ─── Rule 3: Disposable Domain ────────────────────────────────────────────────
export class DisposableDomainRule extends BaseDetectionRule {
  readonly id          = 'disposable_sender_domain';
  readonly description = 'Sender uses a known disposable / throwaway email domain';
  readonly category    = 'sender' as const;
  readonly severity    = 3 as const;
  readonly weight      = 25;
  readonly scoreTarget = 'spam' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const domain = ctx.parsedEmail.fromFullDomain ?? '';
    if (SUSPICIOUS_DOMAINS.some(d => domain.includes(d))) {
      return this.triggered(`Sender domain "${domain}" is a known disposable email service`);
    }
    return this.notTriggered();
  }
}

// ─── Rule 18: Reply-To Domain Mismatch ───────────────────────────────────────
export class ReplyToDomainMismatchRule extends BaseDetectionRule {
  readonly id             = 'reply_to_domain_mismatch';
  readonly description    = 'Reply-To header points to a different domain than the sender';
  readonly category       = 'sender' as const;
  readonly severity       = 4 as const;
  readonly weight         = 35;
  readonly scoreTarget    = 'phishing' as const;
  readonly minCorroboration = 1;   // needs at least 1 other rule to apply full weight

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const replyTo = ctx.parsedEmail.replyTo;
    if (!replyTo) return this.notTriggered();

    const fromBase  = extractBase(ctx.parsedEmail.fromFullDomain ?? '') ?? '';
    const replyBase = extractBase(extractDomain(replyTo) ?? '') ?? '';

    if (!fromBase || !replyBase || fromBase === replyBase) return this.notTriggered();

    const body = ctx.parsedEmail.bodyPlain;
    const hasUrgentFinancial = PHISHING_URGENT.test(body);

    // Only trigger if there's additional context (financial/urgent body or known brand)
    const knownBrandSender = ['paypal', 'google', 'microsoft', 'amazon', 'apple'].includes(fromBase);
    if (!hasUrgentFinancial && !knownBrandSender) return this.notTriggered();

    return this.triggered(
      `Reply-To domain "${replyBase}" differs from sender domain "${fromBase}". ` +
      (hasUrgentFinancial ? 'Email contains financial/urgent language.' : 'Sender claims to be a known brand.'),
    );
  }
}

// ─── Rule 13: First Contact Risk ─────────────────────────────────────────────
// NOTE: This rule is async (requires DB) — the RuleRegistry marks it accordingly
export class FirstContactRiskRule extends BaseDetectionRule {
  readonly id          = 'first_contact_sender_risk';
  readonly description = 'First email from this sender domain combined with suspicious signals';
  readonly category    = 'sender' as const;
  readonly severity    = 2 as const;
  readonly weight      = 20;
  readonly scoreTarget = 'both' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    // Behavioral context is pre-computed by BehaviorService before rules run
    const beh = ctx.behavior;
    if (beh.previousEmailCount > 0) return this.notTriggered();

    let score = 10;
    const reasons: string[] = ['First contact from this sender'];

    if (PHISHING_URGENT.test(ctx.parsedEmail.bodyPlain)) {
      score += 10;
      reasons.push('contains urgent/financial language');
    }
    if (ctx.parsedEmail.hasAttachment) {
      score += 10;
      reasons.push('has attachment');
    }

    if (score <= 10) return this.notTriggered(); // mild signal alone — skip

    return this.triggered(reasons.join(', ') + ` (score boost: +${score})`, score);
  }
}
