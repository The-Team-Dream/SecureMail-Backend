// ─────────────────────────────────────────────────────────────────────────────
// classification.utils.ts
// ─────────────────────────────────────────────────────────────────────────────

import { EmailContentForClassification } from './classification.service';
import { SPAM_KEYWORDS } from './classification.constants';

// ─── Levenshtein Distance ─────────────────────────────────────────────────────
export function levenshtein(a: string, b: string): number {
  const m = a.length, n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)));
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]);
  return dp[m][n];
}

// ─── Fuzzy Keyword Match ──────────────────────────────────────────────────────
export function fuzzyMatchKeyword(text: string, keyword: string): boolean {
  if (text.includes(keyword)) return true;
  const tw = text.split(/\s+/), kw = keyword.split(/\s+/);
  if (kw.length === 1)
    return tw.some(w => w.length > 3 && levenshtein(w, keyword) <= 1);
  for (let i = 0; i <= tw.length - kw.length; i++) {
    if (levenshtein(tw.slice(i, i + kw.length).join(' '), keyword) <= 2) return true;
  }
  return false;
}

// ─── Domain Extraction ────────────────────────────────────────────────────────
// FIX: الـ regex القديمة [a-zA-Z0-9.-] كانت بتوقف عند أي Unicode character
// زي Cyrillic 'а' (а) — يعني 'pаypal.com' كانت بترجع 'p' بس!
// الحل: نمسك كل حاجة بعد الـ @ لحد الـ whitespace أو نهاية الـ string
export function extractDomain(email: string): string | null {
  const match = email.match(/@([^\s@]+)/);
  if (!match) return null;
  // بنعمل lowercase بس على الـ ASCII — الـ Unicode letters بتفضل زي ما هي
  // عشان HOMOGLYPH_MAP يقدر يتعامل معاها
  return match[1].toLowerCase();
}

// ─── extractBaseDomain ────────────────────────────────────────────────────────
// FIX: يدعم multi-part TLDs زي .co.uk و .com.eg
// paypal.co.uk → "paypal"  |  mail.paypal.com → "paypal"
const MULTI_PART_TLDS = new Set([
  'co.uk', 'co.jp', 'co.nz', 'co.za', 'co.in', 'co.kr', 'co.id',
  'com.au', 'com.br', 'com.mx', 'com.ar', 'com.eg', 'com.sa',
  'com.tr', 'com.ng', 'com.pk', 'com.bd', 'com.ph', 'com.sg',
  'net.au', 'org.uk', 'gov.uk', 'ac.uk', 'me.uk',
]);

export function extractBaseDomain(domain: string): string | null {
  if (!domain) return null;
  const parts = domain.split('.');
  if (parts.length < 2) return null;
  const lastTwo = `${parts[parts.length - 2]}.${parts[parts.length - 1]}`;
  if (MULTI_PART_TLDS.has(lastTwo)) {
    return parts.length >= 3 ? parts[parts.length - 3] : null;
  }
  return parts[parts.length - 2];
}

export function extractDomainFromUrl(url: string): string | null {
  try { return new URL(url).hostname.replace(/^www\./, ''); }
  catch { return null; }
}

// ─── Text Helpers ─────────────────────────────────────────────────────────────
export function stripHtml(html: string): string {
  return html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ');
}

export function getCombinedText(email: EmailContentForClassification): string {
  return [
    email.subject  || '',
    email.fromAddr || '',
    email.fromName || '',
    email.bodyText || '',
    stripHtml(email.bodyHtml || ''),
  ].join(' ').replace(/\s+/g, ' ');
}

// ─── URL Helpers ──────────────────────────────────────────────────────────────
export function isIpUrl(text: string): boolean {
  return /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(text);
}

export function isShortenedUrl(url: string, shortenedDomains: string[]): boolean {
  return shortenedDomains.some(d => url.includes(d));
}

// ─── Spam Keywords ────────────────────────────────────────────────────────────
export function countSpamKeywordHits(text: string): number {
  let hits = 0;
  for (const keyword of SPAM_KEYWORDS) {
    if (fuzzyMatchKeyword(text, keyword)) hits++;
  }
  return hits;
}

// ─── Received Headers ─────────────────────────────────────────────────────────
// FIX: بعض الـ parsers (nodemailer/mailparser) بيبعتوا array مش string.
// لو string → نستخدمها directly
// لو array → نجمعها بـ \n عشان منفقدش أي header
export function getAllReceivedHeaders(
  headers: Record<string, string | string[]> | null | undefined,
): string {
  if (!headers) return '';
  const raw = headers['received'] || headers['Received'] || '';
  const normalized = Array.isArray(raw) ? raw.join('\n') : String(raw);
  return normalized.toLowerCase();
}

// ─── Subject-only Text ────────────────────────────────────────────────────────
// للـ rules اللي المنطقي تشتغل على الـ subject بس زي excessive CAPS
export function getSubjectText(email: EmailContentForClassification): string {
  return (email.subject || '').trim();
}

// ─── Body-only Text (بدون fromAddr/fromName) ─────────────────────────────────
// FIX: getCombinedText كانت تضم الـ fromAddr في الـ text
// ده كان بيدي false positives لو الـ domain فيه keyword زي "work" أو "free"
export function getBodyText(email: EmailContentForClassification): string {
  return [
    email.subject  || '',
    email.bodyText || '',
    stripHtml(email.bodyHtml || ''),
  ].join(' ').toLowerCase();
}

// BUG-09 FIX (v14): getBodyText تشمل subject → urgency في subject تُحسب 3 مرات
// subject "URGENT: Verify Your Account" يُفعّل: Rule 8 + Rule 13 amplification + Rule 18 urgency
// getBodyTextOnly() = body فقط — للـ rules اللي الـ subject مش جزء من scope بتاعها
export function getBodyTextOnly(email: EmailContentForClassification): string {
  return [
    email.bodyText || '',
    stripHtml(email.bodyHtml || ''),
  ].join(' ').toLowerCase();
}
