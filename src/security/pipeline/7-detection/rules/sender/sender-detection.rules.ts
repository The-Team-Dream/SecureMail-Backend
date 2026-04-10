// ─────────────────────────────────────────────────────────────────────────────
// detection/rules/sender/sender-detection.rules.ts
//
// Rules:
//   SenderDisplayNameMismatchRule  (Rule 7)
//   DisplayNameImpersonationRule   (Rule 21)
//   DisposableDomainRule           (Rule 3)
//   ReplyToDomainMismatchRule      (Rule 18)
//   FirstContactRiskRule           (Rule 13)
//   SuspiciousIpRule               (Rule 19) ← من ctx.reputation
//   AuthFailureRule                (Rule 20) ← من ctx.authResult
// ─────────────────────────────────────────────────────────────────────────────

import { BaseDetectionRule } from '../detection-rule.interface';
import { DetectionContext } from '../../rule-engine/detection-context';
import {
  BRAND_MAP,
  BRAND_REVERSE_INDEX,
  SENSITIVE_ROLE_KEYWORDS,
  SUSPICIOUS_SENDER_DOMAINS,
  PHISHING_URGENT_PATTERNS,
  WHITELISTED_DOMAINS,
} from 'src/security/constants';
import { RuleResult } from 'src/security/types';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function extractDomain(addr: string): string | null {
  const m = addr.match(/@([^\s@]+)/);
  return m ? m[1].toLowerCase() : null;
}

function extractBase(domain: string): string | null {
  if (!domain) return null;
  const parts = domain.split('.');
  if (parts.length < 2) return null;
  const ccTLD = ['co', 'com', 'net', 'org', 'gov', 'edu', 'ac'];
  if (parts.length >= 3 && ccTLD.includes(parts[parts.length - 2]))
    return parts[parts.length - 3];
  return parts[parts.length - 2];
}

const PHISHING_URGENT = /\b(urgent|immediately|act now|verify account|password expired|wire transfer|gift card)\b/i;

// ─── Rule 19: Suspicious IP / Received Headers ────────────────────────────────
// ✅ يقرأ من ctx.reputation اللي اتحسب بالفعل في Stage 3
// مفيش header parsing — بس تشيك على الـ IpSignals الجاهزة
export class SuspiciousIpRule extends BaseDetectionRule {
  readonly id          = 'suspicious_received_headers';
  readonly description = 'Sender IP is blacklisted, a known attacker, Tor node, or anonymous proxy';
  readonly category    = 'reputation' as const;
  readonly severity    = 4 as const;
  readonly weight      = 25;
  readonly scoreTarget = 'phishing' as const;
  readonly minCorroboration = 1;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    // Stage 3 (Reputation) بتحسب كل الـ IP signals من الـ threat feeds
    const rep = ctx.reputation;
    let score = 0;
    const indicators: string[] = [];

    if (rep.isIpBlacklisted)            { score += 25; indicators.push('sender IP is blacklisted'); }
    if (rep.isKnownAttacker)            { score += 20; indicators.push('IP flagged as known attacker'); }
    if (rep.isIpTor)                    { score += 15; indicators.push('Tor exit node detected'); }
    if (rep.isIpProxy)                  { score += 10; indicators.push('anonymous proxy detected'); }
    if ((rep.ipReputationScore ?? 0) >= 70) {
      score += 15;
      indicators.push(`IP threat score: ${rep.ipReputationScore}/100`);
    }
    if (rep.maliciousEngines && rep.maliciousEngines > 3) {
      score += 10;
      indicators.push(`${rep.maliciousEngines} AV engines flagged this IP`);
    }

    if (score === 0) return this.notTriggered();

    return this.triggered(
      indicators.join(' | '),
      Math.min(score, 30),
    );
  }
}

// ─── Rule 20: Auth Failure (SPF/DKIM/DMARC) ──────────────────────────────────
// ✅ يقرأ من ctx.authResult اللي اتحسب بالفعل في Stage 2
// مفيش header parsing — الـ AuthenticationService بتعمله بالكامل
export class AuthFailureRule extends BaseDetectionRule {
  readonly id          = 'email_auth_failure';
  readonly description = 'SPF, DKIM, or DMARC authentication failed or is missing';
  readonly category    = 'authentication' as const;
  readonly severity    = 4 as const;
  readonly weight      = 25;
  readonly scoreTarget = 'phishing' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const auth = ctx.authResult;
    if (!auth.hasAuthFailure) return this.notTriggered();

    const spf   = auth.spf.status;
    const dkim  = auth.dkim.status;
    const dmarc = auth.dmarc.status;

    let score = 0;

    // Triple failure = almost certainly spoofed sender
    if (spf === 'fail' && dkim === 'fail' && dmarc === 'fail') score = 35;
    else if (spf === 'fail' && dkim === 'fail')                score = 25;
    else if (dmarc === 'fail')                                 score = 20;
    else if (spf === 'fail')                                   score = 15;
    else if (spf === 'softfail')                               score = 10;
    else if (dkim === 'fail')                                  score = 10;

    if (score === 0) return this.notTriggered();

    return this.triggered(
      `Auth failure: SPF=${spf}, DKIM=${dkim}, DMARC=${dmarc} (severity: ${auth.failureSeverity})`,
      score,
    );
  }
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
    const email = ctx.parsedEmail;
    const name  = (email.fromName ?? '').toLowerCase().replace(/[^a-z0-9]/g, '');
    const base  = extractBase(email.fromFullDomain ?? '') ?? '';

    for (const [brand, officialBases] of BRAND_MAP.entries()) {
      if (!/^[a-z0-9]+$/.test(brand)) continue; // skip Arabic aliases
      if (!name.includes(brand)) continue;
      if (officialBases.includes(base)) continue;

      return this.triggered(
        `Display name "${email.fromName}" claims to be "${brand}" but domain is "${email.fromFullDomain}"`,
      );
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

    const senderDomain = ctx.parsedEmail.fromFullDomain ?? '';
    const senderBase   = extractBase(senderDomain) ?? '';

    if (BRAND_REVERSE_INDEX.has(senderBase)) return this.notTriggered();
    if (WHITELISTED_DOMAINS.has(senderDomain)) return this.notTriggered();

    for (const role of SENSITIVE_ROLE_KEYWORDS) {
      const trimmedRole = role.trim();
      let matched = false;

      if (trimmedRole.includes(' ')) {
        // Multi-word phrase: phrase-level boundary
        const escaped = trimmedRole.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        matched = new RegExp('(?:^|\\s)' + escaped + '(?:\\s|$)', 'i').test(name);
      } else {
        // Single word: word boundary
        matched = new RegExp('\\b' + trimmedRole + '\\b', 'i').test(name);
      }

      if (!matched) continue;

      return this.triggered(
        `Display name "${ctx.parsedEmail.fromName}" uses sensitive role "${role}" from unknown domain "${senderDomain}"`,
      );
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
    if (SUSPICIOUS_SENDER_DOMAINS.some(d => domain.includes(d))) {
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
  readonly minCorroboration = 1;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const replyTo = ctx.parsedEmail.replyTo;
    if (!replyTo) return this.notTriggered();

    const fromDomain  = ctx.parsedEmail.fromFullDomain ?? '';
    const fromBase    = extractBase(fromDomain) ?? '';
    const replyBase   = extractBase(extractDomain(replyTo) ?? '') ?? '';

    if (!fromBase || !replyBase || fromBase === replyBase) return this.notTriggered();

    // Known brand sender + different reply-to = definitely suspicious
    if (BRAND_REVERSE_INDEX.has(fromBase)) {
      return this.triggered(
        `Known brand "${fromBase}" has Reply-To pointing to "${replyBase}" — spoofing indicator`,
      );
    }

    const body = ctx.parsedEmail.bodyPlain;

    // Financial/urgent language
    const hasUrgentFinancial =
      PHISHING_URGENT_PATTERNS.some(p => p.test(body)) ||
      /\b(wire transfer|payment|invoice|bank account)\b/i.test(body);
    if (hasUrgentFinancial) {
      return this.triggered(
        `Reply-To "${replyBase}" differs from sender "${fromBase}" with financial/urgent content`,
      );
    }

    // Business context in from-domain
    const hasBusinessContext =
      /\b(order|shipping|invoice|delivery|payment|store|shop|purchase)\b/i.test(fromDomain);
    if (hasBusinessContext) {
      return this.triggered(
        `Reply-To "${replyBase}" differs from business sender domain "${fromDomain}"`,
      );
    }

    return this.notTriggered();
  }
}

// ─── Rule 13: First Contact Risk ─────────────────────────────────────────────
export class FirstContactRiskRule extends BaseDetectionRule {
  readonly id          = 'first_contact_sender_risk';
  readonly description = 'First email from this sender combined with suspicious signals';
  readonly category    = 'sender' as const;
  readonly severity    = 2 as const;
  readonly weight      = 20;
  readonly scoreTarget = 'both' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    // Stage 4 (Behavior) بيجيب previousEmailCount من الـ DB
    if (ctx.behavior.previousEmailCount > 0) return this.notTriggered();

    let score = 10;
    const reasons: string[] = ['First contact from this sender'];

    if (PHISHING_URGENT_PATTERNS.some(p => p.test(ctx.parsedEmail.bodyPlain))) {
      score += 10;
      reasons.push('urgent/financial language');
    }
    if (ctx.parsedEmail.hasAttachment) {
      score += 10;
      reasons.push('has attachment');
    }

    if (score <= 10) return this.notTriggered();

    return this.triggered(reasons.join(', ') + ` (+${score})`, score);
  }
}