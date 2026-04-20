import { Logger } from '@nestjs/common';
import { BaseDetectionRule } from '../detection-rule.interface';
import { DetectionContext } from '../../rule-engine/detection-context';
import {
  HOMOGLYPH_MAP,
  BRAND_MAP,
  ARABIC_BRAND_ALIASES,
  WHITELISTED_DOMAINS,
} from 'src/security/constants';
import { RuleResult } from 'src/security/types';

export type { BaseDetectionRule } from '../detection-rule.interface';

const ALL_OFFICIAL_BASES = new Set<string>([...BRAND_MAP.values()].flat());
const ALL_BRAND_NAMES    = [...BRAND_MAP.keys()];

const CONVERSATION_HIJACK_PATTERNS = [
  /\b(wire\s+transfer|bank\s+transfer)\b/i,
  /\b(update\s+(payment|banking)\s+details?)\b/i,
  /\b(new\s+bank\s+account|change\s+(of\s+)?account)\b/i,
  /\b(urgent\s+payment|payment\s+required)\b/i,
  /\b(updated?\s+(invoice|billing)\s+info(rmation)?)\b/i,
];

const LOOKALIKE_KEYWORDS = [
  'secure', 'login', 'verify', 'account', 'update', 'confirm',
  'auth', 'signin', 'support', 'helpdesk', 'service', 'portal',
];


function extractBase(domain: string): string | null {
  if (!domain) return null;
  const parts = domain.split('.');
  if (parts.length < 2) return null;
  const ccTLD = ['co', 'com', 'net', 'org', 'gov', 'edu', 'ac'];
  if (parts.length >= 3 && ccTLD.includes(parts[parts.length - 2]))
    return parts[parts.length - 3];
  return parts[parts.length - 2];
}

function normalizeHomoglyphs(str: string): string {
  return str.split('').map(c => HOMOGLYPH_MAP[c] ?? c).join('');
}

function stripHtml(html: string): string {
  return html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().toLowerCase();
}

export class MaliciousUrlRule extends BaseDetectionRule {
  readonly id          = 'malicious_url_reputation';
  readonly description = 'A URL in this email was confirmed malicious by threat intelligence feeds';
  readonly category    = 'url' as const;
  readonly severity    = 5 as const;
  readonly weight      = 50;
  readonly scoreTarget = 'phishing' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const urlResult = ctx.urlResult;
    if (!urlResult) return this.notTriggered();

    if (urlResult.hasMaliciousUrl) {
      const maliciousUrls = urlResult.analyzedUrls?.filter(u => u.verdict === 'malicious') ?? [];
      const sources = [...new Set(maliciousUrls.flatMap(u => u.sources ?? []))];

      return this.triggered(
        `${maliciousUrls.length} malicious URL(s) confirmed by: ${sources.join(', ') || 'threat feeds'}`,
        50,
      );
    }

    if (urlResult.totalThreatScore >= 70) {
      return this.triggered(
        `High URL threat score: ${urlResult.totalThreatScore}/100 — ${urlResult.summary}`,
        25,
      );
    }

    return this.notTriggered();
  }
}

export class NewlyRegisteredDomainRule extends BaseDetectionRule {
  readonly id          = 'newly_registered_domain';
  readonly description = 'Sender domain was registered recently — high risk for phishing campaigns';
  readonly category    = 'advanced' as const;
  readonly severity    = 3 as const;
  readonly weight      = 25;
  readonly scoreTarget = 'phishing' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const rep = ctx.reputation;

    if (!rep.newlyRegisteredDomain && (rep.domainAgeDays === undefined || rep.domainAgeDays === null)) {
      return this.notTriggered();
    }

    if (!rep.newlyRegisteredDomain && (rep.domainAgeDays ?? 999) > 90) {
      return this.notTriggered();
    }

    const ageDays = rep.domainAgeDays ?? 0;

    let score = 0;
    if      (ageDays <= 7)  score = 35;
    else if (ageDays <= 30) score = 25;
    else if (ageDays <= 90) score = 10;
    else if (rep.newlyRegisteredDomain) score = 15;

    if (score === 0) return this.notTriggered();

    const isTyposquat = ctx.isTriggered('typosquatting_domain');
    const finalScore  = isTyposquat ? Math.min(score + 10, 45) : score;

    const ageText = rep.domainAgeDays !== undefined
      ? `registered ${ageDays} days ago`
      : 'flagged as newly registered';

    return this.triggered(
      `Sender domain ${ageText}` +
      `${isTyposquat ? ' — also a typosquat (compound risk)' : ''}`,
      finalScore,
    );
  }
}

export class ConversationHijackingRule extends BaseDetectionRule {
  readonly id          = 'conversation_hijacking_attempt';
  readonly description = 'Financial request injected into a reply/forward thread';
  readonly category    = 'headers' as const;
  readonly severity    = 5 as const;
  readonly weight      = 35;
  readonly scoreTarget = 'phishing' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    if (!ctx.parsedEmail.isReplyThread) return this.notTriggered();
    const match = CONVERSATION_HIJACK_PATTERNS.find(p => p.test(ctx.parsedEmail.bodyPlain));
    if (!match) return this.notTriggered();
    return this.triggered(
      `Financial request in reply thread: "${match.source.slice(0, 50)}"`,
    );
  }
}

export class HomoglyphDomainSpoofingRule extends BaseDetectionRule {
  readonly id          = 'homoglyph_domain_spoofing';
  readonly description = 'Sender domain uses Unicode lookalike chars to impersonate a known brand';
  readonly category    = 'advanced' as const;
  readonly severity    = 5 as const;
  readonly weight      = 30;
  readonly scoreTarget = 'phishing' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const domain = ctx.parsedEmail.fromFullDomain ?? '';
    if (!domain) return this.notTriggered();

    const normalized = normalizeHomoglyphs(domain);
    if (normalized === domain) return this.notTriggered();

    const base = extractBase(normalized) ?? '';
    for (const brand of ALL_BRAND_NAMES) {
      if (base === brand || (brand.length > 3 && base.includes(brand))) {
        return this.triggered(
          `Domain "${domain}" normalizes to "${normalized}" — impersonates "${brand}"`,
        );
      }
    }
    return this.notTriggered();
  }
}

export class LookalikeDomainRule extends BaseDetectionRule {
  readonly id          = 'lookalike_domain_attack';
  readonly description = 'Domain contains brand name + phishing keyword (e.g. fawry-verify.net)';
  readonly category    = 'advanced' as const;
  readonly severity    = 4 as const;
  readonly weight      = 30;
  readonly scoreTarget = 'phishing' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const domain = ctx.parsedEmail.fromFullDomain ?? '';
    if (!domain || WHITELISTED_DOMAINS.has(domain)) return this.notTriggered();

    const base         = extractBase(domain) ?? '';
    const matchedBrand = ALL_BRAND_NAMES.find(b => b.length > 2 && domain.includes(b));
    if (!matchedBrand) return this.notTriggered();

    const matchedKw = LOOKALIKE_KEYWORDS.find(kw => domain.includes(kw));
    if (!matchedKw) return this.notTriggered();

    if (ALL_OFFICIAL_BASES.has(base)) return this.notTriggered();

    return this.triggered(
      `Domain "${domain}" impersonates "${matchedBrand}" with keyword "${matchedKw}"`,
    );
  }
}

export class BrandAbuseRule extends BaseDetectionRule {
  readonly id          = 'brand_abuse_in_body';
  readonly description = 'Body mentions a known brand repeatedly but sender is not that brand';
  readonly category    = 'advanced' as const;
  readonly severity    = 3 as const;
  readonly weight      = 20;
  readonly scoreTarget = 'phishing' as const;

  private readonly ACTION_WORDS = [
    'verify', 'confirm', 'update', 'login', 'sign in', 'password',
    'account', 'secure', 'suspended', 'locked', 'click here', 'validate',
  ];

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const senderBase       = extractBase(ctx.parsedEmail.fromFullDomain ?? '') ?? '';
    const senderFullDomain = ctx.parsedEmail.fromFullDomain ?? '';
    const body             = ctx.parsedEmail.bodyPlain;

    if (!body.trim() || WHITELISTED_DOMAINS.has(senderFullDomain)) return this.notTriggered();

    const hasActionWord = this.ACTION_WORDS.some(w => body.includes(w));
    if (!hasActionWord) return this.notTriggered();

    for (const [brand, officialBases] of BRAND_MAP.entries()) {
      if (!/^[a-z0-9]+$/.test(brand)) continue;
      if (officialBases.includes(senderBase)) continue;

      const escaped     = brand.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const mentions    = (body.match(new RegExp('(?:^|\\s)' + escaped + '(?:\\s|$)', 'g')) || []).length;
      const minMentions = brand.length < 5 ? 3 : 2;

      if (mentions >= minMentions) {
        return this.triggered(
          `Brand "${brand}" mentioned ${mentions}× but sender "${senderFullDomain}" is not this brand`,
        );
      }
    }

    for (const [brand, arabicAliases] of ARABIC_BRAND_ALIASES.entries()) {
      const officialBases = BRAND_MAP.get(brand) ?? [];
      if (officialBases.includes(senderBase)) continue;

      for (const alias of arabicAliases) {
        const mentions = body.split(alias).length - 1;
        if (mentions >= 2) {
          return this.triggered(
            `Arabic alias "${alias}" (${brand}) mentioned ${mentions}× but sender is not this brand`,
          );
        }
      }
    }

    return this.notTriggered();
  }
}

export class HTMLObfuscationRule extends BaseDetectionRule {
  readonly id          = 'html_obfuscation_phishing';
  readonly description = 'HTML uses obfuscation: invisible chars, CSS hiding, entity-encoded brands';
  readonly category    = 'advanced' as const;
  readonly severity    = 4 as const;
  readonly weight      = 25;
  readonly scoreTarget = 'phishing' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const html = ctx.parsedEmail.bodyHtml ?? '';
    if (!html) return this.notTriggered();

    if (/[\u200B\u200C\u200D\uFEFF\u00AD\u2060]/.test(html))
      return this.triggered('Zero-width/invisible Unicode characters in HTML');

    if (/[\u202A-\u202E\u2066-\u2069]/.test(html))
      return this.triggered('Unicode bidirectional override characters in HTML');

    if (/style\s*=\s*['"][^'"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)/i.test(html))
      return this.triggered('Content hidden via CSS (display:none / visibility:hidden)');

    if ((html.match(/<!--/g) || []).length > 5)
      return this.triggered('Excessive HTML comment blocks — filter evasion');

    const decoded = html
      .replace(/&#x([0-9a-fA-F]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
      .replace(/&#(\d+);/g,            (_, d) => String.fromCharCode(parseInt(d, 10)));

    if (decoded !== html) {
      const senderBase   = extractBase(ctx.parsedEmail.fromFullDomain ?? '') ?? '';
      const decodedLower = decoded.toLowerCase();
      for (const [brand, officialBases] of BRAND_MAP.entries()) {
        if (!/^[a-z0-9]+$/.test(brand)) continue;
        if (officialBases.includes(senderBase)) continue;
        if (decodedLower.includes(brand)) {
          return this.triggered(
            `HTML entities decode to brand "${brand}" — sender is "${ctx.parsedEmail.fromFullDomain}"`,
          );
        }
      }
    }

    return this.notTriggered();
  }
}

export class Base64EncodedUrlRule extends BaseDetectionRule {
  readonly id          = 'base64_encoded_url';
  readonly description = 'Email contains base64-encoded URLs — scanner evasion technique';
  readonly category    = 'url' as const;
  readonly severity    = 4 as const;
  readonly weight      = 25;
  readonly scoreTarget = 'phishing' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const html = ctx.parsedEmail.bodyHtml ?? '';
    const text = ctx.parsedEmail.bodyPlain ?? '';

    if (/(?:href|src)\s*=\s*['"]data:[^;]+;base64,/i.test(html))
      return this.triggered('data:URI base64-encoded href/src in HTML', 35);

    const combined = [text, stripHtml(html)].join(' ');
    const b64Re    = /\b([A-Za-z0-9+/]{32,}={0,2})\b/g;
    let   m: RegExpExecArray | null;

    while ((m = b64Re.exec(combined)) !== null) {
      if (m[1].length % 4 !== 0) continue;
      try {
        const decoded = Buffer.from(m[1], 'base64').toString('utf-8');
        if (/^https?:\/\//i.test(decoded)) {
          return this.triggered(
            `Base64 decodes to URL: "${decoded.slice(0, 60)}…"`,
            25,
          );
        }
      } catch { continue; }
    }

    return this.notTriggered();
  }
}
