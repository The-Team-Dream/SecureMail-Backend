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

// Known spam keywords and patterns
const SPAM_KEYWORDS = [
  'free money', 'lottery winner', 'congratulations you won', 'claim your prize',
  'act now', 'limited time offer', 'click here', 'buy now', 'viagra', 'cialis',
  'crypto investment', 'bitcoin opportunity', 'nigerian prince', 'urgent action',
  'verify your account', 'unusual activity', 'suspended account', 'click below',
  'dear friend', 'dear customer', 'congratulations', 'you have been selected',
  'no purchase necessary', 'risk free', '100% free', 'guaranteed', 'cash bonus',
  'work from home', 'make money fast', 'instant approval', 'no credit check',
];

// Urgent/phishing language patterns
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

// Common typosquatting patterns (e.g. paypa1.com, g00gle.com)
const TYPO_SQUATTING_PATTERNS = [
  /\bpaypa[1l]\.com\b/i,
  /\bpaypa[1l]\.[a-z]+\b/i,
  /\b(amazon|google|microsoft|apple|netflix|bank)\b.*[0o1l]\.[a-z]+\b/i,
  /\b(amaz0n|g00gle|micr0soft|app1e)\b/i,
];

// Shortened URL patterns
const SHORTENED_URL_DOMAINS = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
  'adf.ly', 'j.mp', 'tr.im', 'cutt.ly', 'shorturl', 'rebrand.ly',
];

// Known suspicious domains (for reputation checks)
const SUSPICIOUS_DOMAINS = [
  'tempmail', 'throwaway', 'guerrillamail', '10minutemail', 'mailinator',
  'fakeinbox', 'trashmail', 'yopmail', 'dispostable',
];

@Injectable()
export class ClassificationService {
  private readonly SPAM_THRESHOLD = 40;
  private readonly PHISHING_THRESHOLD = 30;

  /**
   * Classify an email for spam and phishing.
   * Returns scores and classification flags.
   */
  classify(email: EmailContentForClassification): ClassificationResult {
    const spamScore = this.calculateSpamScore(email);
    const spamPhishingScore = this.calculatePhishingScore(email);

    return {
      isSpam: spamScore >= this.SPAM_THRESHOLD,
      isPhishing: spamPhishingScore >= this.PHISHING_THRESHOLD,
      spamScore: Math.min(100, spamScore),
      phishingScore: Math.min(100, spamPhishingScore),
    };
  }

  private calculateSpamScore(email: EmailContentForClassification): number {
    let score = 0;
    const text = this.getCombinedText(email).toLowerCase();

    // Check spam keywords
    for (const keyword of SPAM_KEYWORDS) {
      if (text.includes(keyword)) {
        score += 8;
      }
    }

    // Check sender domain reputation
    const domain = this.extractDomain(email.fromAddr);
    if (domain && SUSPICIOUS_DOMAINS.some((d) => domain.includes(d))) {
      score += 25;
    }

    // Check for suspicious links
    const linkScore = this.checkSuspiciousLinks(email);
    score += linkScore;

    // Check for excessive caps
    const capsRatio = (text.match(/[A-Z]/g)?.length ?? 0) / Math.max(text.length, 1);
    if (capsRatio > 0.5) score += 10;

    // Check for excessive exclamation marks
    const exclamationCount = (text.match(/!/g) || []).length;
    if (exclamationCount > 3) score += 5;

    return score;
  }

  private calculatePhishingScore(email: EmailContentForClassification): number {
    let score = 0;
    const text = this.getCombinedText(email).toLowerCase();

    // Domain spoofing / typosquatting
    const domain = this.extractDomain(email.fromAddr);
    if (domain && TYPO_SQUATTING_PATTERNS.some((p) => p.test(email.fromAddr))) {
      score += 35;
    }

    // Mismatched sender name vs email domain
    const nameDomainMismatch = this.checkSenderNameDomainMismatch(email);
    if (nameDomainMismatch) score += 25;

    // Urgent language patterns
    for (const pattern of PHISHING_URGENT_PATTERNS) {
      if (pattern.test(text)) {
        score += 10;
        break;
      }
    }

    // Suspicious links
    const linkScore = this.checkPhishingLinks(email);
    score += linkScore;

    // IP-based URLs
    if (this.hasIpBasedUrls(email)) score += 15;

    // Shortened URLs
    if (this.hasShortenedUrls(email)) score += 15;

    return score;
  }

  private getCombinedText(email: EmailContentForClassification): string {
    const parts = [
      email.subject || '',
      email.fromAddr || '',
      email.fromName || '',
      email.bodyText || '',
      this.stripHtml(email.bodyHtml || ''),
    ];
    return parts.join(' ').replace(/\s+/g, ' ');
  }

  private stripHtml(html: string): string {
    return html.replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ');
  }

  private extractDomain(email: string): string | null {
    const match = email.match(/@([a-zA-Z0-9.-]+)/);
    return match ? match[1].toLowerCase() : null;
  }

  private checkSenderNameDomainMismatch(email: EmailContentForClassification): boolean {
    const domain = this.extractDomain(email.fromAddr);
    if (!domain || !email.fromName) return false;

    const trustedDomains = ['paypal.com', 'google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'netflix.com', 'bank'];
    const nameLower = email.fromName.toLowerCase();

    for (const trusted of trustedDomains) {
      if (nameLower.includes(trusted.replace('.com', '')) && !domain.includes(trusted)) {
        return true;
      }
    }
    return false;
  }

  private checkSuspiciousLinks(email: EmailContentForClassification): number {
    let score = 0;
    const html = email.bodyHtml || '';
    const links = html.match(/href=["']([^"']+)["']/gi) || [];
    if (links.length > 5) score += 10;
    return score;
  }

  private checkPhishingLinks(email: EmailContentForClassification): number {
    let score = 0;
    const html = email.bodyHtml || '';
    const hrefMatches = html.matchAll(/href=["']([^"']+)["']/gi);
    const linkTextMatches = html.matchAll(/>([^<]*(?:https?:\/\/[^<]*))</gi);

    for (const match of hrefMatches) {
      const href = match[1];
      if (href.startsWith('http')) {
        if (this.isIpUrl(href)) score += 15;
        if (this.isShortenedUrl(href)) score += 10;
      }
    }

    return Math.min(score, 25);
  }

  private hasIpBasedUrls(email: EmailContentForClassification): boolean {
    const text = this.getCombinedText(email);
    return this.isIpUrl(text);
  }

  private isIpUrl(text: string): boolean {
    return /https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(text);
  }

  private hasShortenedUrls(email: EmailContentForClassification): boolean {
    const text = this.getCombinedText(email);
    return SHORTENED_URL_DOMAINS.some((d) => text.includes(d));
  }

  private isShortenedUrl(url: string): boolean {
    return SHORTENED_URL_DOMAINS.some((d) => url.includes(d));
  }
}
