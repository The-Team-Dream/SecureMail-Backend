// ─────────────────────────────────────────────────────────────────────────────
// detection/rules/advanced/advanced-detection.rules.ts
//
// FIX-1: HOMOGLYPH_MAP imported من classification.constants.ts (single source)
// FIX-2: BRAND_MAP + ARABIC_BRAND_ALIASES imported من classification.constants.ts
//         Egyptian brands (fawry، instapay، meeza، cib، nbe) محمية الآن
// ─────────────────────────────────────────────────────────────────────────────

import { BaseDetectionRule, RuleResult } from '../detection-rule.interface';
import { DetectionContext } from '../../rule-engine/detection-context';

// FIX-1 + FIX-2: single source of truth
import {
  HOMOGLYPH_MAP,
  BRAND_MAP,
  ARABIC_BRAND_ALIASES,
  WHITELISTED_DOMAINS,
} from '../../../../../classification/classification.constants';

export type { DetectionRule, BaseDetectionRule } from '../detection-rule.interface';

// ─── Derived sets (built once at module load) ─────────────────────────────────
const ALL_OFFICIAL_BASES = new Set<string>([...BRAND_MAP.values()].flat());
const ALL_BRAND_NAMES    = [...BRAND_MAP.keys()];

// ─── Shared constants ─────────────────────────────────────────────────────────
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

// ─── Helpers ──────────────────────────────────────────────────────────────────
function extractBase(domain: string): string | null {
  if (!domain) return null;
  const parts = domain.split('.');
  if (parts.length < 2) return domain;
  const ccTLD = ['co', 'com', 'net', 'org', 'gov', 'edu', 'ac'];
  if (parts.length >= 3 && ccTLD.includes(parts[parts.length - 2])) return parts[parts.length - 3];
  return parts[parts.length - 2];
}

// FIX-1: يستخدم HOMOGLYPH_MAP المستورد (Cyrillic + Greek + Latin — 20+ chars)
function normalizeHomoglyphs(str: string): string {
  return str.split('').map(c => HOMOGLYPH_MAP[c] ?? c).join('');
}

function stripHtml(html: string): string {
  return html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().toLowerCase();
}

// ─── Rule 23: Conversation Hijacking ─────────────────────────────────────────
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
      `Financial request in reply thread — matched: "${match.source.slice(0, 50)}"`,
    );
  }
}

// ─── Rule 17: Homoglyph Domain Spoofing ──────────────────────────────────────
// FIX-1: normalizeHomoglyphs يستخدم HOMOGLYPH_MAP الكامل (20+ chars)
// FIX-2: يبحث في ALL_BRAND_NAMES (كل BRAND_MAP، شامل fawry/nbe/cib)
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
          `Domain "${domain}" has homoglyphs → normalized "${normalized}" — impersonating "${brand}".`,
        );
      }
    }
    return this.notTriggered();
  }
}

// ─── Rule 24: Lookalike Domain ───────────────────────────────────────────────
// FIX-2: يستخدم BRAND_MAP بدل MAJOR_BRANDS (14) — يكشف fawry-secure.net إلخ
export class LookalikeDomainRule extends BaseDetectionRule {
  readonly id          = 'lookalike_domain_attack';
  readonly description = 'Domain contains a brand name + phishing keyword (e.g. fawry-verify.net)';
  readonly category    = 'advanced' as const;
  readonly severity    = 4 as const;
  readonly weight      = 30;
  readonly scoreTarget = 'phishing' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const domain = ctx.parsedEmail.fromFullDomain ?? '';
    if (!domain) return this.notTriggered();
    if (WHITELISTED_DOMAINS.has(domain)) return this.notTriggered();

    const base         = extractBase(domain) ?? '';
    const matchedBrand = ALL_BRAND_NAMES.find(b => domain.includes(b));
    if (!matchedBrand) return this.notTriggered();

    const matchedKw = LOOKALIKE_KEYWORDS.find(kw => domain.includes(kw));
    if (!matchedKw) return this.notTriggered();

    // Sender IS the official brand → not suspicious
    if (ALL_OFFICIAL_BASES.has(base)) return this.notTriggered();

    return this.triggered(
      `Domain "${domain}" impersonates "${matchedBrand}" with phishing keyword "${matchedKw}".`,
    );
  }
}

// ─── Rule 16: Brand Abuse in Body ────────────────────────────────────────────
// FIX-2: يستخدم BRAND_MAP (70+ brands) + ARABIC_BRAND_ALIASES
// Egyptian brands (fawry، instapay، meeza) محمية بالعربي والإنجليزي
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
    // Arabic action words للـ Egyptian market
    'تحقق', 'تأكيد', 'تحديث', 'تسجيل', 'كلمة المرور', 'حساب', 'محظور',
  ];

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const senderBase = extractBase(ctx.parsedEmail.fromFullDomain ?? '') ?? '';
    const body       = ctx.parsedEmail.bodyPlain;

    if (!body.trim()) return this.notTriggered();

    // Quick filter — must have at least one action word
    const hasActionWord = this.ACTION_WORDS.some(w => body.includes(w));
    if (!hasActionWord) return this.notTriggered();

    const senderFullDomain = ctx.parsedEmail.fromFullDomain ?? '';
    if (WHITELISTED_DOMAINS.has(senderFullDomain)) return this.notTriggered();

    // ── Phase 1: English brands (BRAND_MAP — 70+ entries) ────────────────────
    for (const [brand, officialBases] of BRAND_MAP.entries()) {
      if (officialBases.includes(senderBase)) continue; // sender IS the brand

      const escaped     = brand.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const regex       = new RegExp('(?:^|\\s)' + escaped + '(?:\\s|$)', 'g');
      const mentions    = (body.match(regex) || []).length;
      const minMentions = brand.length < 5 ? 3 : 2;

      if (mentions >= minMentions) {
        return this.triggered(
          `Brand "${brand}" mentioned ${mentions}× but sender "${senderFullDomain}" is not this brand.`,
        );
      }
    }

    // ── Phase 2: Arabic aliases (Egyptian market) ─────────────────────────────
    for (const [brand, arabicAliases] of ARABIC_BRAND_ALIASES.entries()) {
      const officialBases = BRAND_MAP.get(brand) ?? [];
      if (officialBases.includes(senderBase)) continue;

      for (const alias of arabicAliases) {
        const mentions = body.split(alias).length - 1;
        if (mentions >= 2) {
          return this.triggered(
            `Arabic alias "${alias}" (${brand}) mentioned ${mentions}× but sender is not this brand.`,
          );
        }
      }
    }

    return this.notTriggered();
  }
}

// ─── Rule 25: HTML Obfuscation ────────────────────────────────────────────────
// FIX-2: entity decode check يستخدم BRAND_MAP keys بدل MAJOR_BRANDS
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

    // 1. Zero-width / invisible chars
    if (/[\u200B\u200C\u200D\uFEFF\u00AD\u2060]/.test(html)) {
      return this.triggered('HTML contains zero-width/invisible Unicode characters');
    }
    // 2. Bidi override
    if (/[\u202A-\u202E\u2066-\u2069]/.test(html)) {
      return this.triggered('HTML contains Unicode bidirectional override characters');
    }
    // 3. CSS hiding
    if (/style\s*=\s*['"][^'"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)/i.test(html)) {
      return this.triggered('HTML hides content via CSS (display:none, visibility:hidden, font-size:0)');
    }
    // 4. Excessive HTML comments
    if ((html.match(/<!--/g) || []).length > 5) {
      return this.triggered('HTML has excessive comment blocks — filter evasion technique');
    }

    // 5. HTML entity-encoded brand names — FIX-2: BRAND_MAP keys
    const decoded = html
      .replace(/&#x([0-9a-fA-F]+);/gi, (_, h) => String.fromCharCode(parseInt(h, 16)))
      .replace(/&#(\d+);/g,            (_, d) => String.fromCharCode(parseInt(d, 10)));

    if (decoded !== html) {
      const senderBase   = extractBase(ctx.parsedEmail.fromFullDomain ?? '') ?? '';
      const decodedLower = decoded.toLowerCase();
      for (const [brand, officialBases] of BRAND_MAP.entries()) {
        if (officialBases.includes(senderBase)) continue;
        if (decodedLower.includes(brand)) {
          return this.triggered(
            `HTML entity-encoded text decodes to brand "${brand}" ` +
            `but sender is "${ctx.parsedEmail.fromFullDomain}" — evasion.`,
          );
        }
      }
    }

    return this.notTriggered();
  }
}

// ─── Rule 26: Base64 Encoded URL ─────────────────────────────────────────────
export class Base64EncodedUrlRule extends BaseDetectionRule {
  readonly id          = 'base64_encoded_url';
  readonly description = 'Email contains base64-encoded URLs — evasion technique';
  readonly category    = 'url' as const;
  readonly severity    = 4 as const;
  readonly weight      = 25;
  readonly scoreTarget = 'phishing' as const;

  evaluate(ctx: Readonly<DetectionContext>): RuleResult {
    const html = ctx.parsedEmail.bodyHtml ?? '';
    const text = ctx.parsedEmail.bodyPlain ?? '';

    if (/(?:href|src)\s*=\s*['"]data:[^;]+;base64,/i.test(html)) {
      return this.triggered('data:URI base64-encoded href/src in HTML', 35);
    }

    const combined = [text, stripHtml(html)].join(' ');
    const b64Re    = /\b([A-Za-z0-9+/]{32,}={0,2})\b/g;
    let   m: RegExpExecArray | null;

    while ((m = b64Re.exec(combined)) !== null) {
      if (m[1].length % 4 !== 0) continue;
      try {
        const decoded = Buffer.from(m[1], 'base64').toString('utf-8');
        if (/^https?:\/\//i.test(decoded)) {
          return this.triggered(
            `Base64-decoded URL: "${decoded.slice(0, 60)}…" — URL scanner evasion.`,
            25,
          );
        }
      } catch { continue; }
    }

    return this.notTriggered();
  }
}
