// ─────────────────────────────────────────────────────────────────────────────
// classification/rules/domain.rules.ts  (SECURITY FIX — Rule 27 WHOIS)
//
// GAP FIXED: Rule 27 "Newly Registered Domain" is now ACTIVE.
//
// Implementation uses RDAP (Registration Data Access Protocol) via rdap.org:
//   - Free, no API key required
//   - Standardized JSON response (RFC 7483)
//   - Results cached in-memory (Map) with 24h TTL to avoid hammering the API
//
// Note: Full Redis cache integration requires injecting RedisService here.
// For graduation project scope, in-memory Map cache is sufficient and correct.
// Redis migration path is documented in the TODO comment below.
//
// Scoring:
//   - Domain registered < 7 days ago  → +35 (very high risk)
//   - Domain registered < 30 days ago → +25 (high risk)
//   - Domain registered < 90 days ago → +10 (elevated risk)
//   - Amplification: if also typosquatting → +10 bonus (compound)
//
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable, Logger } from '@nestjs/common';
import { EmailContentForClassification } from '../classification.service';
import {
  BRAND_MAP,
  BRAND_REVERSE_INDEX,
  HOMOGLYPH_MAP,
  SUSPICIOUS_TLDS,
  LOOKALIKE_PHISHING_KEYWORDS,
} from '../classification.constants';
import {
  extractDomain,
  extractBaseDomain,
  levenshtein,
  getAllReceivedHeaders,
} from '../classification.utils';

// ─── RDAP response shape (RFC 7483) ──────────────────────────────────────────
interface RdapEvent {
  eventAction: string;  // 'registration', 'expiration', 'last changed', etc.
  eventDate:   string;  // ISO 8601 date string
}

interface RdapResponse {
  events?: RdapEvent[];
}

// ─── In-memory cache entry ────────────────────────────────────────────────────
interface CacheEntry {
  score:     number;
  expiresAt: number;   // Date.now() + 24h
}

@Injectable()
export class DomainRules {

  private readonly logger = new Logger(DomainRules.name);

  // ── In-memory WHOIS cache (domain → score)
  // TTL: 24 hours. Domain registration dates don't change frequently.
  //
  // TODO (production): migrate to Redis injection:
  //   constructor(@InjectRedis() private redis: Redis) {}
  //   await redis.set(`whois:${domain}`, score, 'EX', 86400);
  //   const cached = await redis.get(`whois:${domain}`);
  private readonly whoisCache = new Map<string, CacheEntry>();
  private readonly WHOIS_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 24 hours

  // ─── RDAP endpoint — free, no key, RFC-standard ───────────────────────────
  private readonly RDAP_BASE = 'https://rdap.org/domain';

  // ─── Newly registered domain thresholds ──────────────────────────────────
  private readonly AGE_THRESHOLDS = [
    { maxDays: 7,  score: 35 },   // very suspicious — brand new domain
    { maxDays: 30, score: 25 },   // high risk — < 1 month
    { maxDays: 90, score: 10 },   // elevated — < 3 months
  ] as const;

  async check(email: EmailContentForClassification, reasons: string[]): Promise<number> {
    let score = 0;

    // Rule 6 — Typosquatting
    const isTyposquatting = this.checkTyposquatting(email.fromAddr);
    if (isTyposquatting) {
      score += 35;
      reasons.push('typosquatting_domain');
    }

    // Rule 11 — Suspicious TLD
    const tldScore = this.checkSuspiciousTld(email);
    if (tldScore > 0) {
      score += tldScore;
      reasons.push('suspicious_sender_tld');
    }

    // Rule 17 — Homoglyph / Unicode Spoofing
    if (this.checkHomoglyph(email.fromAddr)) {
      score += 30;
      reasons.push('homoglyph_domain_spoofing');
    }

    // Rule 19 — Received Headers Chain
    const headersScore = this.checkReceivedHeaders(email);
    if (headersScore > 0) {
      score += headersScore;
      reasons.push('suspicious_received_headers');
    }

    // Rule 20 — SPF / DKIM / DMARC
    const authScore = this.checkAuthFailure(email);
    if (authScore > 0) {
      score += authScore;
      reasons.push('email_auth_failure');
    }

    // Rule 24 — Advanced Lookalike Domain
    if (this.checkLookalikeDomain(email.fromAddr)) {
      score += 30;
      reasons.push('lookalike_domain_attack');
    }

    // ── Rule 27 — Newly Registered Domain [NOW ACTIVE] ────────────────────────
    const whoisScore = await this.checkNewlyRegisteredDomain(email.fromAddr);
    if (whoisScore > 0) {
      score += whoisScore;
      reasons.push('newly_registered_domain');

      // Compound amplification: newly registered + typosquatting = very high confidence
      // A fresh domain that's also a typosquat of a brand = almost certainly malicious
      if (isTyposquatting) {
        score += 10;
        reasons.push('newly_registered_typosquat_compound');
      }
    }

    return score;
  }

  // ─── Rule 27: Newly Registered Domain ────────────────────────────────────
  /**
   * Queries RDAP (rdap.org) to find the domain registration date.
   * Returns a risk score based on how recently the domain was registered.
   *
   * Phishing campaigns typically use fresh domains because:
   *   1. They have no reputation history → harder to blocklist
   *   2. They're cheap to register → throwaway after campaign
   *   3. Fresh domains bypass age-based email filters
   *
   * Flow:
   *   1. Extract base domain from sender address
   *   2. Check in-memory cache (24h TTL)
   *   3. If cache miss → query rdap.org/domain/{domain}
   *   4. Parse 'registration' event date from RDAP response
   *   5. Compute age in days → map to score
   *   6. Cache result → return score
   *
   * Non-fatal: any network error returns 0 (fail-open — avoids false positives)
   */
  private async checkNewlyRegisteredDomain(fromAddr: string): Promise<number> {
    const domain = extractDomain(fromAddr);
    if (!domain) return 0;

    const baseDomain = extractBaseDomain(domain);
    if (!baseDomain) return 0;

    // Use full domain for RDAP (e.g. 'paypal-secure.xyz' not just 'paypal-secure')
    const queryDomain = domain;

    // ── Cache check ───────────────────────────────────────────────────────────
    const cached = this.whoisCache.get(queryDomain);
    if (cached && Date.now() < cached.expiresAt) {
      return cached.score;
    }

    // ── RDAP lookup ───────────────────────────────────────────────────────────
    try {
      const url = `${this.RDAP_BASE}/${queryDomain}`;

      // Timeout: 3 seconds — we don't want WHOIS to block email processing
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 3000);

      const response = await fetch(url, {
        signal: controller.signal,
        headers: { 'Accept': 'application/rdap+json' },
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        // Domain not found in RDAP or RDAP error → treat as unknown (score 0)
        this.cacheResult(queryDomain, 0);
        return 0;
      }

      const data = await response.json() as RdapResponse;
      const score = this.computeAgeScore(data, queryDomain);

      this.cacheResult(queryDomain, score);
      return score;

    } catch (err) {
      // Network error / timeout / RDAP unavailable → fail-open (score 0)
      // We never want WHOIS lookup failure to cause false positives
      this.logger.warn(`[Rule27] RDAP lookup failed for ${queryDomain}`, {
        error: err instanceof Error ? err.message : String(err),
      });
      return 0;
    }
  }

  private computeAgeScore(data: RdapResponse, domain: string): number {
    const events = data.events ?? [];

    // Find the 'registration' event (may also appear as 'domain registration')
    const registrationEvent = events.find(
      e => e.eventAction === 'registration' || e.eventAction === 'domain registration'
    );

    if (!registrationEvent?.eventDate) {
      // No registration date available → can't determine age → score 0
      return 0;
    }

    const registeredAt  = new Date(registrationEvent.eventDate);
    const now           = new Date();
    const ageMs         = now.getTime() - registeredAt.getTime();
    const ageDays       = Math.floor(ageMs / (1000 * 60 * 60 * 24));

    // Map age to risk score
    for (const threshold of this.AGE_THRESHOLDS) {
      if (ageDays <= threshold.maxDays) {
        this.logger.log(`[Rule27] ${domain} registered ${ageDays} days ago → score +${threshold.score}`);
        return threshold.score;
      }
    }

    // Domain is > 90 days old → not suspicious by age alone
    return 0;
  }

  private cacheResult(domain: string, score: number): void {
    this.whoisCache.set(domain, {
      score,
      expiresAt: Date.now() + this.WHOIS_CACHE_TTL_MS,
    });
  }

  // ─── Rule 6: Typosquatting ──────────────────────────────────────────────────
  private checkTyposquatting(fromAddr: string): boolean {
    const fullDomain = extractDomain(fromAddr);
    if (!fullDomain) return false;
    const normalizedDomain = fullDomain.split('').map(ch => HOMOGLYPH_MAP[ch] ?? ch).join('');
    const senderBase = extractBaseDomain(normalizedDomain);
    if (!senderBase) return false;

    // FIX: Brand-as-subdomain-prefix attack
    // e.g. paypal.attacker.ru → fullDomain starts with 'paypal.' but base is 'attacker'
    // e.g. google.phishing-site.com → fullDomain starts with 'google.' but base is 'phishing-site'
    for (const [, officialBases] of BRAND_MAP) {
      for (const official of officialBases) {
        // Check if the FULL domain starts with the brand followed by a dot (subdomain prefix trick)
        if (normalizedDomain.startsWith(`${official}.`) && senderBase !== official) {
          return true;
        }
      }
    }

    // Fuzzy match on base domain (existing logic)
    for (const [, officialBases] of BRAND_MAP) {
      for (const official of officialBases) {
        if (senderBase === official) continue;
        const maxDist = official.length >= 3 && official.length <= 4 ? 1 : 2;
        if (levenshtein(senderBase, official) <= maxDist) return true;
      }
    }
    return false;
  }

  // ─── Rule 11: Suspicious TLD ────────────────────────────────────────────────
  private checkSuspiciousTld(email: EmailContentForClassification): number {
    const domain = extractDomain(email.fromAddr);
    if (!domain) return 0;
    const tld = domain.split('.').pop()?.toLowerCase();
    if (!tld) return 0;
    if (SUSPICIOUS_TLDS.includes(tld)) return 20;
    return 0;
  }

  // ─── Rule 17: Homoglyph ─────────────────────────────────────────────────────
  private checkHomoglyph(fromAddr: string): boolean {
    const domain = extractDomain(fromAddr);
    if (!domain) return false; 
    for (const ch of domain) {
      if (HOMOGLYPH_MAP[ch]) return true;
    }
    return false;
  }

  // ─── Rule 19: Received Headers ──────────────────────────────────────────────
  private checkReceivedHeaders(email: EmailContentForClassification): number {
    if (!email.headers) return 0;
    const headers = getAllReceivedHeaders(email.headers);
    if (headers.length === 0) return 0;

    // FIX: Rule 19 = brand sender but mail didn't pass through brand's servers
    // e.g. "From: support@paypal.com" but Received headers show no paypal.com server
    const fromDomain  = extractDomain(email.fromAddr) ?? '';
    const senderBase  = extractBaseDomain(fromDomain) ?? '';

    // Only apply the brand-mismatch check to known brand senders
    if (BRAND_REVERSE_INDEX.has(senderBase)) {
      const allHeaders = headers.toLowerCase();
      // If none of the Received headers mention the brand's domain → suspicious
      if (!allHeaders.includes(senderBase)) {
        return 25;
      }
      return 0;
    }

    // Fallback: IP-only / localhost relay (original logic — for non-brand senders)
    let score = 0;
    const ipOnlyPattern    = /from\s+\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i;
    const localhostPattern = /from\s+(localhost|127\.0\.0\.1)/i;
    for (const h of headers) {
      if (localhostPattern.test(h)) { score += 20; break; }
      if (ipOnlyPattern.test(h))    { score += 10; break; }
    }
    return Math.min(score, 25);
  }

  // ─── Rule 20: SPF/DKIM/DMARC ────────────────────────────────────────────────
  private checkAuthFailure(email: EmailContentForClassification): number {
    if (!email.headers) return 0;
    const authRaw = email.headers['authentication-results'] || email.headers['Authentication-Results'] || '';
    const auth = (Array.isArray(authRaw) ? authRaw.join(' ') : String(authRaw)).toLowerCase();
    if (!auth) return 0;
    const spfHardFail = /spf=fail\b/.test(auth);          // fail بس (مش softfail)
    const spfSoftFail = /spf=softfail/.test(auth);
    const spfFail   = spfHardFail || spfSoftFail
    const dkimFail  = /dkim=(fail|none)/.test(auth);
    const dmarcFail = /dmarc=(fail)/.test(auth);

    if (spfFail && dkimFail && dmarcFail) return 35;
    if (spfFail && dkimFail)  return 25;
    if (dmarcFail) return 20;
    if (spfHardFail)  return 15;   // hard fail = 15
    if (spfSoftFail)  return 10;   // soft fail = 10 (أقل من hard fail)
    if (dkimFail)  return 10;
    return 0;
  }

  // ─── Rule 24: Lookalike Domain ──────────────────────────────────────────────
  private checkLookalikeDomain(fromAddr: string): boolean {
    const domain = extractDomain(fromAddr);
    if (!domain) return false;
    const lower = domain.toLowerCase();
    return LOOKALIKE_PHISHING_KEYWORDS.some(kw => lower.includes(kw));
  }
}
