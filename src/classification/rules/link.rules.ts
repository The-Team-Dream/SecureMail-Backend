// ─────────────────────────────────────────────────────────────────────────────
// rules/link.rules.ts
//
// Rule 9  — IP-based URLs
// Rule 10 — Shortened URLs
// Rule 12 — Link Mismatch (visible text vs actual href)
// Rule 25 — HTML Obfuscation Detection
// Rule 26 — Base64 Encoded URLs
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable } from '@nestjs/common';
import { EmailContentForClassification } from '../classification.service';
import { BRAND_MAP, BRAND_REVERSE_INDEX, SHORTENED_URL_DOMAINS, TRUSTED_SENDING_SERVICES } from '../classification.constants';
import {
  extractDomain,
  extractBaseDomain,
  extractDomainFromUrl,
  stripHtml,
  isIpUrl,
  isShortenedUrl,
} from '../classification.utils';

@Injectable()
export class LinkRules {

  check(email: EmailContentForClassification, reasons: string[]): number {
    let score = 0;

    if (this.hasIpBasedUrls(email)) {
      score += 15;
      reasons.push('ip_based_url');
    }

    if (this.hasShortenedUrls(email)) {
      score += 15;
      reasons.push('shortened_url');
    }

    if (this.checkLinkMismatch(email)) {
      score += 30;
      reasons.push('html_link_text_mismatch');
    }

    if (this.checkHtmlObfuscation(email)) {
      score += 25;
      reasons.push('html_obfuscation_phishing');
    }

    const base64Score = this.checkBase64Urls(email);
    if (base64Score > 0) {
      score += base64Score;
      reasons.push('base64_encoded_url');
    }

    // NOTE: IP + shortened URL scoring handled by Rules 9/10 — no double-count
    return score;
  }

  // ─── Rule 9: IP-based URLs ───────────────────────────────────────────────────
  private hasIpBasedUrls(email: EmailContentForClassification): boolean {
    const text = [email.subject || '', email.bodyText || '', email.bodyHtml || ''].join(' ');
    return isIpUrl(text);
  }

  // ─── Rule 10: Shortened URLs ─────────────────────────────────────────────────
  private hasShortenedUrls(email: EmailContentForClassification): boolean {
    const text = [email.bodyText || '', email.bodyHtml || ''].join(' ');
    return isShortenedUrl(text, SHORTENED_URL_DOMAINS);
  }

  // ─── Rule 12: Link Mismatch ──────────────────────────────────────────────────
  /**
   * FIX: الـ regex القديمة كان فيها typo — bracket زيادة بعد الـ URL:
   *   ['\"']  بدل  ['"]
   * ده كان بيخلي الـ regex تفوّت كتير من الـ links.
   *
   * الـ regex الصح:
   *   <a  [^>]+  href=['"]  (URL)  ['"]  [^>]*>  (TEXT)  </a>
   *                                ^^^
   *                          single closing bracket
   */
  private checkLinkMismatch(email: EmailContentForClassification): boolean {
    const html = email.bodyHtml || '';
    // FIX: ['"] مش ['\"'] — الأخيرة bracket زيادة كانت بتكسر الـ matching
    const anchorRegex = /<a[^>]+href=['"](https?:\/\/[^'"]+)['"][^>]*>(.*?)<\/a>/gi;
    let match: RegExpExecArray | null;

    while ((match = anchorRegex.exec(html)) !== null) {
      const actualUrl   = match[1].trim().toLowerCase();
      const visibleText = stripHtml(match[2]).trim().toLowerCase();

      if (!visibleText.includes('.') || visibleText.includes(' ')) continue;

      const actualHostname  = extractDomainFromUrl(actualUrl);
      const visibleHostname = extractDomainFromUrl(
        visibleText.startsWith('http') ? visibleText : `https://${visibleText}`,
      );
      if (!actualHostname || !visibleHostname) continue;

      // FIX: قارن الـ base domain مش الـ full hostname
      // em.paypal.com vs paypal.com → base: paypal === paypal → OK (مش false positive)
      // evil.ru vs paypal.com       → base: evil !== paypal   → FLAGGED ✓
      const actualBase  = extractBaseDomain(actualHostname)  ?? actualHostname;
      const visibleBase = extractBaseDomain(visibleHostname) ?? visibleHostname;

      if (actualBase !== visibleBase) return true;
    }
    return false;
  }

  // ─── Rule 25: HTML Obfuscation ───────────────────────────────────────────────
  private checkHtmlObfuscation(email: EmailContentForClassification): boolean {
    const html = email.bodyHtml || '';
    if (!html) return false;

    // 1. Zero-width / invisible characters
    if (/[\u200B\u200C\u200D\uFEFF\u00AD\u2060]/.test(html)) return true;

    // 2. Unicode bidirectional override
    if (/[\u202A-\u202E\u2066-\u2069]/.test(html)) return true;

    // 3. CSS hiding tricks
    if (/style\s*=\s*['"][^'"]*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|opacity\s*:\s*0)/i.test(html)) return true;

    // 4. Excessive HTML comments
    if ((html.match(/<!--/g) || []).length > 5) return true;

    // 5. HTML entity brand obfuscation
    // FIX: decode both decimal AND hex entities
    // Phishers use hex encoding (&#x70;&#x61;&#x79;... = "paypal") to bypass scanners
    // Decimal: &#112; = 'p' | Hex: &#x70; = 'p'
    const decoded = html
      .replace(/&#x([0-9a-fA-F]+);/gi, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
      .replace(/&#(\d+);/g,           (_, dec) => String.fromCharCode(parseInt(dec, 10)));
    if (decoded !== html) {
      const senderDomain = extractDomain(email.fromAddr) ?? '';
      const senderBase   = extractBaseDomain(senderDomain) ?? '';

      // لو من trusted ESP → مش obfuscation
      if (TRUSTED_SENDING_SERVICES.some(s => senderDomain.includes(s))) return false;

      const decodedLower = decoded.toLowerCase();
      for (const [brand, officialBases] of BRAND_MAP) {
        // FIX: المقارنة الصح — هل الـ sender هو صاحب البراند المذكور تحديداً؟
        // BRAND_REVERSE_INDEX.has(senderBase) كان أعم من اللازم:
        // email من google.com وجسمه فيه &#112;&#97;&#121;&#112;&#97;&#108; (paypal)
        // كان بيعدي لأن google هو brand معروف — بغض النظر عن PayPal
        if (decodedLower.includes(brand) && !officialBases.includes(senderBase)) return true;
      }
    }

    return false;
  }

  // ─── Rule 26: Base64 Encoded URLs ────────────────────────────────────────────
  private checkBase64Urls(email: EmailContentForClassification): number {
    let score = 0;
    const html     = email.bodyHtml || '';
    const bodyText = email.bodyText || '';

    // Pattern A: data URI in href/src
    if (/(?:href|src)\s*=\s*['"]data:[^;]+;base64,/i.test(html)) {
      score += 35;
    }

    // Pattern B: standalone Base64 blocks in body
    const combined = [bodyText, stripHtml(html)].join(' ');
    const b64Regex = /\b([A-Za-z0-9+/]{32,}={0,2})\b/g;
    let match: RegExpExecArray | null;

    while ((match = b64Regex.exec(combined)) !== null) {
      const candidate = match[1];
      if (candidate.length % 4 !== 0) continue;

      let decoded: string;
      try { decoded = Buffer.from(candidate, 'base64').toString('utf-8'); }
      catch { continue; }

      const nonPrintable = (decoded.match(/[^\x20-\x7E]/g) || []).length;
      if (nonPrintable / decoded.length > 0.3) continue;

      const decodedLower = decoded.toLowerCase();

      if (/^https?:\/\//i.test(decoded)) {
        score += 25;
        if (isIpUrl(decoded))                              score += 10;
        if (isShortenedUrl(decoded, SHORTENED_URL_DOMAINS)) score += 5;

        const decodedDomain = extractDomainFromUrl(decoded);
        if (decodedDomain) {
          const senderBase = extractBaseDomain(extractDomain(email.fromAddr) ?? '') ?? '';
          // FIX: O(1) sender check بدل officialBases.includes() loop
          for (const brand of BRAND_MAP.keys()) {
            if (decodedDomain.includes(brand) && !BRAND_REVERSE_INDEX.has(senderBase)) {
              score += 15;
              break;
            }
          }
        }
        break;
      }

      const phishingActionWords = ['verify', 'login', 'password', 'account', 'confirm', 'secure'];
      // بنلف على BRAND_MAP.keys() هنا عشان محتاجين نشوف لو أي brand اتذكر في الـ decoded text
      const hasBrand  = [...BRAND_MAP.keys()].some(b => b.length > 3 && decodedLower.includes(b));
      const hasAction = phishingActionWords.some(w => decodedLower.includes(w));
      if (hasBrand && hasAction) { score += 20; break; }
    }

    return Math.min(score, 40);
  }

}

