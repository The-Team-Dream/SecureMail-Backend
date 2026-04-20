import { BaseDetectionRule } from '../detection-rule.interface';
import { DetectionContext } from '../../rule-engine/detection-context';
import {
  PHISHING_URGENT_PATTERNS,
  BEC_PATTERNS,
  RISKY_ATTACHMENT_EXTENSIONS,
  FINANCIAL_ATTACHMENT_KEYWORDS,
  WHITELISTED_DOMAINS,
  TRUSTED_SENDING_SERVICES,
} from 'src/security/constants';
import { RuleResult } from 'src/security/types';


function extractDomainFromUrl(url: string): string | null {
  try { return new URL(url).hostname.toLowerCase(); }
  catch { return null; }
}

function extractBaseDomain(domain: string): string | null {
  if (!domain) return null;
  const parts = domain.split('.');
  if (parts.length < 2) return null;
  const ccTLD = ['co', 'com', 'net', 'org', 'gov', 'edu', 'ac'];
  if (parts.length >= 3 && ccTLD.includes(parts[parts.length - 2]))
    return parts[parts.length - 3];
  return parts[parts.length - 2];
}

function isIpUrl(url: string): boolean {
  return /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url);
}

const ARCHIVE_EXTENSIONS = new Set(['.zip', '.rar', '.7z', '.gz', '.tar', '.iso']);
export class IpBasedUrlRule extends BaseDetectionRule {
  readonly id = 'ip_based_url';
  readonly description = 'Email contains a URL with a raw IP address instead of a domain name';
  readonly category = 'url' as const;
  readonly severity = 3 as const;
  readonly weight = 15;
  readonly scoreTarget = 'phishing' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const hasIpUrl = ctx.urlResult?.analyzedUrls?.some(u => u.isIpBased) ?? false;
    if (!hasIpUrl) return this.notTriggered();

    const count = ctx.urlResult?.analyzedUrls?.filter(u => u.isIpBased).length ?? 0;
    return this.triggered(
      `${count} IP-based URL(s) detected — attackers use raw IPs to bypass domain blacklists`,
    );
  }
}
export class ShortenedUrlRule extends BaseDetectionRule {
  readonly id = 'shortened_url';
  readonly description = 'Email contains a shortened URL that hides the real destination';
  readonly category = 'url' as const;
  readonly severity = 3 as const;
  readonly weight = 15;
  readonly scoreTarget = 'phishing' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const hasShortened = ctx.urlResult?.analyzedUrls?.some(u => u.isShortened) ?? false;
    if (!hasShortened) return this.notTriggered();

    const count = ctx.urlResult?.analyzedUrls?.filter(u => u.isShortened).length ?? 0;
    return this.triggered(
      `${count} shortened URL(s) detected — destination domain is hidden`,
    );
  }
}

export class UrgentPhishingLanguageRule extends BaseDetectionRule {
  readonly id = 'urgent_phishing_language';
  readonly description = 'Email contains urgency or threatening language typical of phishing';
  readonly category = 'content' as const;
  readonly severity = 3 as const;
  readonly weight = 10;
  readonly scoreTarget = 'phishing' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const text = ctx.parsedEmail.bodyPlain.toLocaleLowerCase().replace(/[^a-zA-Z\s]/g, '');
    const matchedPattern = PHISHING_URGENT_PATTERNS.find(p => p.test(text));
    if (!matchedPattern) return this.notTriggered();
    return this.triggered(
      `Urgent/threatening phishing language: "${matchedPattern.source.slice(0, 40)}…"`,
    );
  }
}

export class BECLanguageRule extends BaseDetectionRule {
  readonly id = 'bec_language_detected';
  readonly description = 'Business Email Compromise patterns: financial requests, secrecy instructions';
  readonly category = 'content' as const;
  readonly severity = 4 as const;
  readonly weight = 25;
  readonly scoreTarget = 'phishing' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const text = ctx.parsedEmail.bodyPlain;
    const hits = BEC_PATTERNS.filter(p => p.test(text));
    if (hits.length === 0) return this.notTriggered();

    const score = Math.min(hits.length * 10, 25);
    return this.triggered(
      `BEC patterns (${hits.length}): ` + hits.slice(0, 2).map(p => p.source.slice(0, 30)).join('; '),
      score,
    );
  }
}

export class CredentialHarvestingRule extends BaseDetectionRule {
  readonly id = 'credential_harvesting_attempt';
  readonly description = 'HTML body contains login forms or password inputs pointing to external domains';
  readonly category = 'content' as const;
  readonly severity = 5 as const;
  readonly weight = 50;
  readonly scoreTarget = 'phishing' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const html = ctx.parsedEmail.bodyHtml ?? '';
    if (!html) return this.notTriggered();

    const hasPasswordInput = /<input[^>]+type\s*=\s*['"]?password['"]?/i.test(html);
    let score = 0;

    if (hasPasswordInput) score += 40;

    let hasWhitelistedForm = false;
    let hasExternalForm = false;

    const formActionRegex = /<form[^>]+action\s*=\s*['"]?(https?:\/\/[^'">\s]+)['"]?/gi;
    let match: RegExpExecArray | null;

    while ((match = formActionRegex.exec(html)) !== null) {
      const actionUrl = match[1];
      const actionDomain = extractDomainFromUrl(actionUrl) ?? '';
      const actionBase = extractBaseDomain(actionDomain) ?? '';

      const actionIsWhitelisted =
        WHITELISTED_DOMAINS.has(actionDomain) ||
        WHITELISTED_DOMAINS.has(`${actionBase}.com`) ||
        TRUSTED_SENDING_SERVICES.some(s => actionDomain.includes(s));

      if (actionIsWhitelisted) { hasWhitelistedForm = true; break; }

      hasExternalForm = true;
      if (hasPasswordInput) score += 30;
      else score += 10;

      // IP-based form action = extra red flag
      if (isIpUrl(actionUrl)) score += 15;
      break;
    }

    if (score === 0 && !hasWhitelistedForm && !hasExternalForm && /<form[\s>]/i.test(html)) {
      score += 5;
    }

    if (score === 0) return this.notTriggered();

    return this.triggered(
      `HTML contains ${hasPasswordInput ? 'password input' : 'form'}` +
      `${hasExternalForm ? ' with external action' : ''}` +
      `${isIpUrl(html) ? ' (IP-based)' : ''} — credential harvesting`,
      Math.min(score, 50),
    );
  }
}

export class ExcessiveCapitalizationRule extends BaseDetectionRule {
  readonly id = 'excessive_capitalization';
  readonly description = 'Subject or body has more than 50% uppercase characters — spam indicator';
  readonly category = 'content' as const;
  readonly severity = 2 as const;
  readonly weight = 10;
  readonly scoreTarget = 'spam' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const text = (`${ctx.parsedEmail.subject} ${ctx.parsedEmail.bodyPlain}`)
      .replace(/https?:\/\/\S+/g, '')
      .replace(/[^a-zA-Z\s]/g, '');
    const letters = text.match(/[a-zA-Z]/g)?.length ?? 0;
    const uppercase = text.match(/[A-Z]/g)?.length ?? 0;
    if (letters === 0) return this.notTriggered();
    const capsRatio = uppercase / letters;
    if (capsRatio <= 0.25) return this.notTriggered();
    return this.triggered(
      `${Math.round(capsRatio * 100)}% uppercase (threshold: 30%)`
    );
  }

}

export class ExcessiveExclamationRule extends BaseDetectionRule {
  readonly id = 'excessive_exclamation_marks';
  readonly description = 'More than 3 exclamation marks in email body — spam indicator';
  readonly category = 'content' as const;
  readonly severity = 1 as const;
  readonly weight = 5;
  readonly scoreTarget = 'spam' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const count = (ctx.parsedEmail.bodyPlain.match(/!/g) || []).length;
    if (count <= 3) return this.notTriggered();
    return this.triggered(`${count} exclamation marks (threshold: 3)`);
  }
}

export class RiskyAttachmentRule extends BaseDetectionRule {
  readonly id = 'risky_attachment_detected';
  readonly description = 'Email contains executable, script, or high-risk file type';
  readonly category = 'attachment' as const;
  readonly severity = 4 as const;
  readonly weight = 20;
  readonly scoreTarget = 'phishing' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    if (!ctx.parsedEmail.hasAttachment) return this.notTriggered();

    let score = 0;
    const flagged: string[] = [];
    const hasPhishContext = PHISHING_URGENT_PATTERNS.some(p => p.test(ctx.parsedEmail.bodyPlain));
    const bodyLower = ctx.parsedEmail.bodyPlain.toLowerCase();
    const hasFinancialCtx = FINANCIAL_ATTACHMENT_KEYWORDS.some(k => bodyLower.includes(k));

    for (const att of ctx.parsedEmail.attachments) {
      const ext = att.filename.substring(att.filename.lastIndexOf('.')).toLowerCase();

      if (RISKY_ATTACHMENT_EXTENSIONS.includes(ext) && !ARCHIVE_EXTENSIONS.has(ext)) {
        score += 20;
        if (hasPhishContext) score += 10;
        flagged.push(`${att.filename} (executable)`);
      } else if (ARCHIVE_EXTENSIONS.has(ext)) {
        score += hasPhishContext ? 15 : 10;
        flagged.push(`${att.filename} (archive)`);
      } else if (['.pdf', '.doc', '.docx', '.xls', '.xlsx'].includes(ext)) {
        if (hasFinancialCtx) {
          score += 15;
          flagged.push(`${att.filename} (office+financial)`);
        }
      }
    }

    if (score === 0) return this.notTriggered();

    return this.triggered(
      `Risky attachment(s): ${flagged.slice(0, 3).join(', ')}` +
      `${hasPhishContext ? ' (phishing context)' : ''}`,
      Math.min(score, 30),
    );
  }
}
