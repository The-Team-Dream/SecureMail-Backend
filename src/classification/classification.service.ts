// ─────────────────────────────────────────────────────────────────────────────
// classification.service.ts  —  Orchestrator
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable, Logger } from '@nestjs/common';
import { DomainRules }  from './rules/domain.rules';
import { LinkRules }    from './rules/link.rules';
import { ContentRules } from './rules/content.rules';
import { SenderRules }  from './rules/sender.rules';
import { HeaderRules }  from './rules/header.rules';
import { WHITELISTED_DOMAINS, RULE_WEIGHTS, RULE_DESCRIPTIONS, BRAND_MAP, BRAND_REVERSE_INDEX, PHISHING_RULE_IDS } from './classification.constants';
import { extractDomain, extractBaseDomain }  from './classification.utils';

// ─── Rule Hit — returned per triggered rule ───────────────────────────────────
export interface RuleHit {
  rule:        string;   // rule identifier e.g. 'reply_to_domain_mismatch'
  score:       number;   // score contribution of this rule
  description: string;   // human-readable explanation
}

export interface ClassificationResult {
  isSpam:        boolean;
  isPhishing:    boolean;
  spamScore:     number;
  phishingScore: number;
  reasons:       string[];   // kept for backward compat
  ruleHits:      RuleHit[];  // full explanation per triggered rule
}

export interface EmailContentForClassification {
  subject:      string;
  fromAddr:     string;
  fromName?:    string;
  replyTo?:     string | null;
  bodyText?:    string | null;
  bodyHtml?:    string | null;
  headers?:     Record<string, string | string[]> | null;
  attachments?: { filename: string; mimeType: string }[];
  mailBoxId?:   number;
}

@Injectable()
export class ClassificationService {
  private readonly SPAM_THRESHOLD     = 40;
  private readonly PHISHING_THRESHOLD = 30;

  constructor(
    private readonly domainRules:  DomainRules,
    private readonly linkRules:    LinkRules,
    private readonly contentRules: ContentRules,
    private readonly senderRules:  SenderRules,
    private readonly headerRules:  HeaderRules,
    // TODO: InfrastructureRules (Rules 27+28) — uncomment when WHOIS/VirusTotal APIs ready
    // private readonly infrastructureRules: InfrastructureRules,
    // ثم في classify(): const infraScore = await this.infrastructureRules.check(email, reasons);
    // وتضيفه في rawPhishingScore = ... + infraScore
    // وتضيف InfrastructureRules في classification.module.ts providers[]
  ) {}

  // ── Error Resilience ─────────────────────────────────────────────────────
  // IMP-05 FIX: console.error → NestJS Logger — structured logging للـ production
  // console.error ممكن يتجاهل في production environments
  // Logger.error بيدخل في الـ NestJS logging pipeline (Datadog, CloudWatch, etc.)
  private readonly logger = new Logger(ClassificationService.name);

  private async safeRun<T>(fn: () => Promise<T> | T, fallback: T): Promise<T> {
    try { return await fn(); }
    catch (err) {
      // Structured error: rule function name + error message للـ monitoring
      this.logger.error('[rule-group-error]', {
        rule:    fn.name || 'anonymous',
        message: err instanceof Error ? err.message : String(err),
        stack:   err instanceof Error ? err.stack   : undefined,
      });
      return fallback;
    }
  }

  async classify(email: EmailContentForClassification): Promise<ClassificationResult> {
    const reasons: string[] = [];

    // ── Whitelist check ───────────────────────────────────────────────────────
    // FIX: الـ whitelist مش bypass كامل — هي fast-path hint بس
    // لازم SPF/DKIM يكون pass الأول عشان نثق إن الـ email فعلاً جاي من الـ domain ده
    // لو مفيش auth headers خالص (headers = null) → نكمل عادي ونشغل الـ rules
    // لو فيه auth headers وفيه fail → مش موثوق حتى لو الـ domain في الـ whitelist
    const isKnownDomain = this.isWhitelisted(email.fromAddr);
    if (isKnownDomain) {
      // FIX: بنعامل null و undefined بنفس الطريقة — كلاهما = "مفيش headers"
      // EmailContentForClassification بيعرّف headers كـ null بس،
      // لكن الـ IMAP parser ممكن يبعت undefined — نحمي الاتنين
      const headers = email.headers ?? null;
      if (!headers) {
        // مفيش headers خالص → نثق في الـ whitelist وبس
        return { isSpam: false, isPhishing: false, spamScore: 0, phishingScore: 0, reasons: [], ruleHits: [] };
      }
      const authRaw = headers['authentication-results'] || headers['Authentication-Results'] || '';
      const auth = (Array.isArray(authRaw) ? authRaw.join(' ') : String(authRaw)).toLowerCase();
      const hasAuthInfo = auth.length > 0;
      const authPassed  = hasAuthInfo && !/spf=(fail|softfail|none)/.test(auth) && !/dkim=(fail|none)/.test(auth);
      // لو الـ auth pass أو مفيش authentication-results header (مش كل ESPs بيبعتوه) → safe
      if (!hasAuthInfo || authPassed) {
        return { isSpam: false, isPhishing: false, spamScore: 0, phishingScore: 0, reasons: [], ruleHits: [] };
      }
      // لو الـ domain موثوق لكن SPF/DKIM fail → attacker يتظاهر — نكمل الـ rules كلها
    }

    // ── Run all rule groups ───────────────────────────────────────────────────
    // ARCH NOTE: Promise.all مقصود حتى لو الـ sync rules — للتوافق مع InfrastructureRules
    // لما تتضاف كـ async (WHOIS/VirusTotal) هتشتغل parallel مع الباقي بدون تعديل هنا
    const [
      domainScore,
      linkScore,
      contentResult,
      senderScores,
      headerScore,
    ] = await Promise.all([
      this.safeRun(() => this.domainRules.check(email, reasons), 0),
      this.safeRun(() => this.linkRules.check(email, reasons),   0),
      this.safeRun(() => this.contentRules.check(email, reasons), { spamScore: 0, phishingScore: 0 }),
      this.safeRun(() => this.senderRules.check(email, reasons), { spamScore: 0, phishingScore: 0 }),
      this.safeRun(() => this.headerRules.check(email, reasons), 0),
    ]);

    // FIX: ContentRules بترجع { spamScore, phishingScore }
    // credential_harvesting يروح لـ phishingScore — مش contentScore (spam bucket)
    const contentSpamScore     = contentResult.spamScore;
    const contentPhishingScore = contentResult.phishingScore;

    const uniqueReasons = [...new Set(reasons)];

    // ── Confidence Multiplier ─────────────────────────────────────────────────
    // المشكلة: rule واحدة score عالي (زي reply_to_mismatch = 35) كانت بتعدي
    // الـ threshold لوحدها من غير corroboration.
    //
    // الحل: لو rule محتاجة corroboration (minCorroboration > 0) وما فيش
    // rules تانية اتفعلت معاها → نطبق penalty 0.5 على الـ score بتاعها.
    //
    // مثال:
    //   reply_to_mismatch (35) لوحده    → 35 * 0.5 = 17.5 → مش phishing
    //   reply_to_mismatch + auth_failure → 35 + 35 = 70   → phishing ✓
    const rawPhishingScore = domainScore + linkScore + contentPhishingScore + senderScores.phishingScore + headerScore;
    const adjustedPhishingScore = this.applyConfidenceMultiplier(uniqueReasons, rawPhishingScore);

    const spamScore     = Math.min(100, contentSpamScore + senderScores.spamScore);
    const phishingScore = Math.min(100, adjustedPhishingScore);

    // Build ruleHits — base weight per rule (approximate, not actual contribution)
    // ملاحظة: بعض الـ rules بتضيف أكتر من الـ base weight (زي spam_keywords = hits × 8)
    // الـ score هنا = الـ base weight المعرّف في RULE_WEIGHTS — مش الـ contribution الفعلية
    // ده كافي للـ frontend يعرض الـ severity النسبية بين الـ rules
    const ruleHits: RuleHit[] = uniqueReasons.map(rule => ({
      rule,
      score:       RULE_WEIGHTS[rule]?.score ?? 0,
      description: RULE_DESCRIPTIONS[rule] ?? rule,
    }));

    return {
      isSpam:        spamScore     >= this.SPAM_THRESHOLD,
      isPhishing:    phishingScore >= this.PHISHING_THRESHOLD,
      spamScore,
      phishingScore,
      reasons:   uniqueReasons,
      ruleHits,
    };
  }

  // ─── Whitelist Check ─────────────────────────────────────────────────────────
  /**
   * FIX: الإصدار القديم كان بيبني `${base}.com` بس — مش هيشتغل مع:
   *   - google.co.uk   → base = "google" → بيبني "google.com" ✓ بالصدفة
   *   - amazon.com.au  → base = "amazon" → بيبني "amazon.com" ✓ بالصدفة
   *   - fawry.com.eg   → base = "fawry"  → بيبني "fawry.com"  ✗ مش في الـ whitelist
   *
   * الحل: بنبني كل الـ domain combinations الممكنة وبنشوف لو أي منهم في الـ whitelist
   *
   * مثال لـ "mail.amazon.com.au":
   *   parts = ['mail', 'amazon', 'com', 'au']
   *   نجرب: mail.amazon.com.au / amazon.com.au / com.au / au
   *   amazon.com.au موجود؟ لأ — بس amazon موجودة في BRAND_MAP
   *   فبنشوف لو الـ base domain في أي brand official bases
   */
  private isWhitelisted(fromAddr: string): boolean {
    const domain = extractDomain(fromAddr);
    if (!domain) return false;

    // Direct match — e.g. fawry.com
    if (WHITELISTED_DOMAINS.has(domain)) return true;

    // Subdomain match — e.g. mail.google.com → google.com
    const parts = domain.split('.');
    for (let i = 1; i < parts.length - 1; i++) {
      const candidate = parts.slice(i).join('.');
      if (WHITELISTED_DOMAINS.has(candidate)) return true;
    }

    // Base domain match across all TLD variants using BRAND_MAP
    // e.g. amazon.com.au → base = "amazon" → in BRAND_MAP official bases → whitelisted
    const base = extractBaseDomain(domain);
    if (!base) return false;

    // ملاحظة: لا نستخدم BRAND_REVERSE_INDEX.has(base) هنا عمداً
    // BRAND_MAP مصممة للـ impersonation detection مش للـ whitelist
    // استخدامها في الـ whitelist كان بيعمل overgeneralization:
    //   base='x'  → x.ai, x.org كلها whitelisted (بسبب twitter bases)
    //   base='me' → me.com, me.io كلها whitelisted (بسبب apple bases)
    //   base='t'  → t.ly, t.io كلها whitelisted (بسبب twitter bases)
    // الـ whitelist بتعتمد على WHITELISTED_DOMAINS + subdomain matching بس
    return false;
  }

  // ─── Confidence Multiplier ────────────────────────────────────────────────────
  // بنحسب كام rule اتفعلت اللي محتاجة corroboration
  // لو rule محتاجة corroboration ومفيش حاجة تانية معاها → نقلل وزنها
  private applyConfidenceMultiplier(reasons: string[], rawScore: number): number {
    // FIX: نحسب الـ multiplier على الـ phishing-specific reasons بس
    // مش على كل الـ reasons — لأن الـ rawPhishingScore نفسه جاي من phishing rules
    // وإحنا مش عايزين spam rules (زي spam_keywords) تأثر على الـ phishing confidence
    const phishingReasons = reasons.filter(r => PHISHING_RULE_IDS.has(r));
    const count = phishingReasons.length;

    if (count === 0) return 0;

    // لو phishing rule واحدة بس اتفعلت وهي محتاجة corroboration → penalty
    if (count === 1) {
      const rule   = phishingReasons[0];
      const weight = RULE_WEIGHTS[rule];
      if (weight && weight.minCorroboration > 0) {
        return rawScore * 0.5;
      }
    }

    // لو phishing rules كتير → bonus multiplier
    // 2 rules → 1.0x  |  3 rules → 1.1x  |  4+ rules → 1.2x
    if (count >= 4) return rawScore * 1.2;
    if (count >= 3) return rawScore * 1.1;
    return rawScore;
  }
}
