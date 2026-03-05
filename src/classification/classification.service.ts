import { Injectable } from '@nestjs/common';

export interface ClassificationResult {
  isSpam: boolean;
  isPhishing: boolean;
  spamScore: number;
  phishingScore: number;
}

export interface EmailContentForClassification {
  subject: string;
  fromAddr: string;
  fromName?: string;
  bodyText?: string | null;
  bodyHtml?: string | null;
}

// ─── Spam Keywords ────────────────────────────────────────────────────────────
const SPAM_KEYWORDS = [
  'free money', 'lottery winner', 'congratulations you won', 'claim your prize',
  'act now', 'limited time offer', 'click here', 'buy now', 'viagra', 'cialis',
  'crypto investment', 'bitcoin opportunity', 'nigerian prince', 'urgent action',
  'verify your account', 'unusual activity', 'suspended account', 'click below',
  'dear friend', 'dear customer', 'congratulations', 'you have been selected',
  'no purchase necessary', 'risk free', '100% free', 'guaranteed', 'cash bonus',
  'work from home', 'make money fast', 'instant approval', 'no credit check',
  'earn money', 'double your income', 'special promotion', 'exclusive offer',
  'you are a winner', 'claim now', 'prize money', 'get paid', 'passive income',
];

// ─── Phishing Urgent Patterns ─────────────────────────────────────────────────
const PHISHING_URGENT_PATTERNS = [
  /\b(account\s+(suspended|locked|disabled|compromised))\b/i,
  /\b(verify\s+(your|now|immediately))\b/i,
  /\b(confirm\s+(your|now))\b/i,
  /\b(urgent|immediate|asap|act now)\b/i,
  /\b(security\s+alert|suspicious\s+activity)\b/i,
  /\b(password\s+expired|reset\s+password)\b/i,
  /\b(update\s+your\s+information)\b/i,
  /\b(click\s+here\s+to\s+(verify|confirm|update))\b/i,
  /\b(verify\s+identity|confirm\s+identity)\b/i,
  /\b(unauthorized\s+access|someone\s+tried)\b/i,
  /\b(limited\s+time|expires\s+soon|within\s+\d+\s*hours?)\b/i,
];

// ─── Shortened URL Domains ────────────────────────────────────────────────────
const SHORTENED_URL_DOMAINS = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
  'adf.ly', 'j.mp', 'tr.im', 'cutt.ly', 'shorturl', 'rebrand.ly',
];

// ─── Suspicious Sender Domains ────────────────────────────────────────────────
const SUSPICIOUS_SENDER_DOMAINS = [
  'tempmail', 'throwaway', 'guerrillamail', '10minutemail', 'mailinator',
  'fakeinbox', 'trashmail', 'yopmail', 'dispostable', 'sharklasers',
  'getairmail', 'spamgourmet', 'mytrashmail', 'mailnull',
];

// ─── Brand Map ────────────────────────────────────────────────────────────────
// key   = keyword that might appear in the display name
// value = list of legitimate base domains for that brand
const BRAND_MAP = new Map<string, string[]>([
  ['paypal',     ['paypal']],
  ['google',     ['google', 'gmail', 'youtube', 'googlemail']],
  ['microsoft',  ['microsoft', 'outlook', 'live', 'hotmail', 'office', 'msn']],
  ['apple',      ['apple', 'icloud', 'me']],
  ['amazon',     ['amazon', 'aws', 'amazonses']],
  ['netflix',    ['netflix']],
  ['facebook',   ['facebook', 'fb', 'meta', 'instagram', 'whatsapp']],
  ['instagram',  ['instagram', 'fb', 'meta']],
  ['twitter',    ['twitter', 'x', 't']],
  ['linkedin',   ['linkedin']],
  ['github',     ['github', 'githubusercontent']],
  ['dropbox',    ['dropbox']],
  ['stripe',     ['stripe']],
  ['shopify',    ['shopify', 'myshopify']],
  ['zoom',       ['zoom', 'zoomgov']],
  ['slack',      ['slack']],
  ['adobe',      ['adobe']],
  ['spotify',    ['spotify']],
  ['uber',       ['uber']],
  ['airbnb',     ['airbnb']],
  ['binance',    ['binance']],
  ['coinbase',   ['coinbase']],
  ['ebay',       ['ebay']],
  ['alibaba',    ['alibaba', 'aliexpress', 'taobao']],
  ['tiktok',     ['tiktok', 'bytedance']],
  ['samsung',    ['samsung']],
  ['vodafone',   ['vodafone']],
  ['orange',     ['orange']],
  ['etisalat',   ['etisalat', 'eand']],
  ['we',         ['te', 'tedata']],
  // Egyptian Banks
  ['cib',        ['cib', 'cibeg']],
  ['nbe',        ['nbe', 'nbe-eg']],
  ['alexbank',   ['alexbank']],
  ['banque',     ['banquemisr']],
  ['qnb',        ['qnb', 'qnbalahli']],
  ['hsbc',       ['hsbc']],
  ['fawry',      ['fawry']],
  ['instapay',   ['instapay']],
]);

@Injectable()
export class ClassificationService {
  private readonly SPAM_THRESHOLD     = 40;
  private readonly PHISHING_THRESHOLD = 30;

  // ─── Public API ─────────────────────────────────────────────────────────────
  classify(email: EmailContentForClassification): ClassificationResult {
    const spamScore     = this.calculateSpamScore(email);
    const phishingScore = this.calculatePhishingScore(email);

    return {
      isSpam:       spamScore     >= this.SPAM_THRESHOLD,
      isPhishing:   phishingScore >= this.PHISHING_THRESHOLD,
      spamScore:    Math.min(100, spamScore),
      phishingScore: Math.min(100, phishingScore),
    };
  }

  // ─── Spam Score ──────────────────────────────────────────────────────────────
  private calculateSpamScore(email: EmailContentForClassification): number {
    let score = 0;
    const text = this.getCombinedText(email).toLowerCase();

    // 1. Fuzzy keyword matching (tolerates 1-char mutations like "fr-ee money")
    for (const keyword of SPAM_KEYWORDS) {
      if (this.fuzzyMatchKeyword(text, keyword)) {
        score += 8;
      }
    }

    // 2. Suspicious sender domain (temp mail services)
    const domain = this.extractDomain(email.fromAddr);
    if (domain && SUSPICIOUS_SENDER_DOMAINS.some(d => domain.includes(d))) {
      score += 25;
    }

    // 3. Excessive links in HTML body
    const linkScore = this.checkExcessiveLinks(email);
    score += linkScore;

    // 4. Excessive capital letters ratio
    const capsRatio = (text.match(/[A-Z]/g)?.length ?? 0) / Math.max(text.length, 1);
    if (capsRatio > 0.5) score += 10;

    // 5. Excessive exclamation marks
    const exclamationCount = (text.match(/!/g) || []).length;
    if (exclamationCount > 3) score += 5;

    return score;
  }

  // ─── Phishing Score ──────────────────────────────────────────────────────────
  private calculatePhishingScore(email: EmailContentForClassification): number {
    let score = 0;
    const text = this.getCombinedText(email).toLowerCase();

    // 1. Typosquatting — Levenshtein distance on sender domain vs known brands
    if (this.checkTyposquatting(email.fromAddr)) {
      score += 35;
    }

    // 2. Display name / sender domain mismatch
    if (this.checkSenderNameDomainMismatch(email)) {
      score += 25;
    }

    // 3. Urgent/threatening language patterns
    for (const pattern of PHISHING_URGENT_PATTERNS) {
      if (pattern.test(text)) {
        score += 10;
        break; // count once even if multiple patterns match
      }
    }

    // 4. Links with raw IP addresses (http://192.168.x.x/...)
    if (this.hasIpBasedUrls(email)) score += 15;

    // 5. Shortened URLs in body
    if (this.hasShortenedUrls(email)) score += 15;

    // 6. Phishing links in HTML (IP or shortened URLs in href)
    score += this.checkPhishingLinks(email);

    return score;
  }

  // ─── Levenshtein Distance (no external dependency) ───────────────────────────
  /**
   * Classic dynamic-programming Levenshtein distance.
   * Returns the minimum number of single-character edits
   * (insertions, deletions, substitutions) to transform a → b.
   */
  private levenshtein(a: string, b: string): number {
    const m = a.length;
    const n = b.length;

    // dp[i][j] = edit distance between a[0..i-1] and b[0..j-1]
    const dp: number[][] = Array.from({ length: m + 1 }, (_, i) =>
      Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0)),
    );

    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        if (a[i - 1] === b[j - 1]) {
          dp[i][j] = dp[i - 1][j - 1];
        } else {
          dp[i][j] = 1 + Math.min(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]);
        }
      }
    }
    return dp[m][n];
  }

  // ─── Fuzzy Keyword Match ─────────────────────────────────────────────────────
  /**
   * Matches keyword against text allowing up to 1 edit per word.
   * Handles tricks like "fr-ee money" or "v!agra".
   */
  private fuzzyMatchKeyword(text: string, keyword: string): boolean {
    // Fast path — exact match
    if (text.includes(keyword)) return true;

    const textWords    = text.split(/\s+/);
    const keywordWords = keyword.split(/\s+/);

    if (keywordWords.length === 1) {
      // Single word — check each word in text
      return textWords.some(
        w => w.length > 3 && this.levenshtein(w, keyword) <= 1,
      );
    }

    // Multi-word keyword — sliding window over text words
    for (let i = 0; i <= textWords.length - keywordWords.length; i++) {
      const chunk = textWords.slice(i, i + keywordWords.length).join(' ');
      if (this.levenshtein(chunk, keyword) <= 2) return true;
    }
    return false;
  }

  // ─── Typosquatting Detection ─────────────────────────────────────────────────
  /**
   * Extracts the effective base domain from the sender address
   * and checks if it closely resembles any known brand domain.
   *
   * Catches:
   *  - paypa1.com        (char substitution)
   *  - paypall.com       (extra char)
   *  - paypal.net        (same base, different TLD)
   *  - paypal.com.evil.ru (brand as subdomain of attacker domain)
   */
  private checkTyposquatting(fromAddr: string): boolean {
    const fullDomain = this.extractDomain(fromAddr);
    if (!fullDomain) return false;

    const senderBase = this.extractBaseDomain(fullDomain);
    if (!senderBase) return false;

    for (const [, officialBases] of BRAND_MAP) {
      for (const official of officialBases) {
        // Exact match means it is legitimate — skip
        if (senderBase === official) continue;

        // Very close to official base (1-2 char difference)
        if (
          official.length > 3 &&
          this.levenshtein(senderBase, official) <= 2
        ) {
          return true;
        }

        // Brand domain used as a subdomain of attacker domain
        // e.g. fullDomain = "paypal.com.evil.ru" → base = "evil", but fullDomain contains "paypal.com."
        if (fullDomain.includes(`${official}.com.`) ||
            fullDomain.includes(`${official}.net.`) ||
            fullDomain.includes(`${official}.org.`)) {
          return true;
        }
      }
    }
    return false;
  }

  // ─── Sender Name / Domain Mismatch ───────────────────────────────────────────
  /**
   * Detects emails where the display name claims to be a trusted brand
   * but the actual sending domain is not an official domain for that brand.
   *
   * Example:
   *   fromName = "PayPal Security"
   *   fromAddr = "noreply@paypa1-secure.com"
   *   → mismatch = true (+25)
   */
  private checkSenderNameDomainMismatch(
    email: EmailContentForClassification,
  ): boolean {
    const fullDomain = this.extractDomain(email.fromAddr);
    if (!fullDomain || !email.fromName) return false;

    const senderBase = this.extractBaseDomain(fullDomain) ?? '';
    const nameLower  = email.fromName.toLowerCase().replace(/[^a-z0-9]/g, '');

    for (const [brand, officialBases] of BRAND_MAP) {
      // Display name mentions the brand
      if (!nameLower.includes(brand)) continue;

      // Check if the actual sending domain is one of the official bases
      const isOfficial = officialBases.some(base => senderBase === base);
      if (!isOfficial) return true;
    }
    return false;
  }

  // ─── Link Checks ─────────────────────────────────────────────────────────────
  private checkExcessiveLinks(email: EmailContentForClassification): number {
    const html  = email.bodyHtml || '';
    const links = html.match(/href=[\"']([^\"']+)[\"']/gi) || [];
    return links.length > 5 ? 10 : 0;
  }

  private checkPhishingLinks(email: EmailContentForClassification): number {
    let score = 0;
    const html        = email.bodyHtml || '';
    const hrefMatches = html.matchAll(/href=[\"']([^\"']+)[\"']/gi);

    for (const match of hrefMatches) {
      const href = match[1];
      if (!href.startsWith('http')) continue;
      if (this.isIpUrl(href))       score += 15;
      if (this.isShortenedUrl(href)) score += 10;
    }
    return Math.min(score, 25);
  }

  private hasIpBasedUrls(email: EmailContentForClassification): boolean {
    return this.isIpUrl(this.getCombinedText(email));
  }

  private hasShortenedUrls(email: EmailContentForClassification): boolean {
    const text = this.getCombinedText(email);
    return SHORTENED_URL_DOMAINS.some(d => text.includes(d));
  }

  private isIpUrl(text: string): boolean {
    return /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(text);
  }

  private isShortenedUrl(url: string): boolean {
    return SHORTENED_URL_DOMAINS.some(d => url.includes(d));
  }

  // ─── Utilities ───────────────────────────────────────────────────────────────
  private getCombinedText(email: EmailContentForClassification): string {
    return [
      email.subject   || '',
      email.fromAddr  || '',
      email.fromName  || '',
      email.bodyText  || '',
      this.stripHtml(email.bodyHtml || ''),
    ].join(' ').replace(/\s+/g, ' ');
  }

  private stripHtml(html: string): string {
    return html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ');
  }

  /**
   * Extracts the full domain from an email address.
   * "user@mail.paypal.com" → "mail.paypal.com"
   */
  private extractDomain(email: string): string | null {
    const match = email.match(/@([a-zA-Z0-9.-]+)/);
    return match ? match[1].toLowerCase() : null;
  }

  /**
   * Extracts the registrable base domain (without subdomains or TLD).
   * Uses a simple heuristic: second-to-last label before the TLD.
   *
   * "mail.paypal.com"        → "paypal"
   * "paypal.com.evil.ru"     → "evil"    ← attacker domain exposed
   * "paypa1-secure.com"      → "paypa1-secure"
   *
   * Note: for production accuracy consider the `tldts` npm package,
   * but this heuristic covers the vast majority of phishing cases.
   */
  private extractBaseDomain(domain: string): string | null {
    const parts = domain.split('.');
    if (parts.length < 2) return null;
    // Return the label just before the TLD
    return parts[parts.length - 2];
  }
}
