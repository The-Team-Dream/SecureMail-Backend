// ─────────────────────────────────────────────────────────────────────────────
// rules/infrastructure.rules.ts
//
// Rules that require external API calls or network lookups.
// Each rule has a clear STUB comment showing exactly what to plug in.
//
// Rule 27 — Newly Registered Domain  (STUB — needs WHOIS API)
// Rule 28 — URL Reputation Check     (STUB — needs VirusTotal / GSB API)
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable, Logger } from '@nestjs/common';
import { EmailContentForClassification } from '../classification.service';
import { extractDomain } from '../classification.utils';

@Injectable()
export class InfrastructureRules {
  private readonly logger = new Logger(InfrastructureRules.name);

  async check(
    email: EmailContentForClassification,
    reasons: string[],
  ): Promise<number> {
    let score = 0;

    // Rule 27 — Newly Registered Domain
    const domainAgeScore = await this.checkNewlyRegisteredDomain(email.fromAddr);
    if (domainAgeScore > 0) {
      score += domainAgeScore;
      reasons.push('newly_registered_domain');
    }

    // Rule 28 — URL Reputation
    const urlReputationScore = await this.checkUrlReputation(email);
    if (urlReputationScore > 0) {
      score += urlReputationScore;
      reasons.push('malicious_url_reputation');
    }

    return score;
  }

  // ─── Rule 27: Newly Registered Domain ───────────────────────────────────────
  /**
   * Phishing domains are usually registered days before the attack.
   * A domain < 30 days old + brand impersonation = very high risk.
   *
   * STATUS: STUB — returns 0 until WHOIS API is plugged in.
   *
   * ══════════════════════════════════════════════════════════
   * HOW TO IMPLEMENT:
   *
   * Option A — whoisxmlapi.com (recommended, has free tier)
   *   const res = await fetch(
   *     `https://www.whoisxmlapi.com/whoisserver/WhoisService` +
   *     `?apiKey=${process.env.WHOIS_API_KEY}` +
   *     `&domainName=${domain}&outputFormat=JSON`
   *   );
   *   const data = await res.json();
   *   const createdDate = data.WhoisRecord?.createdDate;
   *
   * Option B — rdap (free, no API key, rate limited)
   *   const res = await fetch(`https://rdap.org/domain/${domain}`);
   *   const data = await res.json();
   *   const createdDate = data.events?.find(e => e.eventAction === 'registration')?.eventDate;
   *
   * Scoring logic (plug in after getting createdDate):
   *   const ageInDays = (Date.now() - new Date(createdDate).getTime()) / 86_400_000;
   *   if (ageInDays < 7)  return 40;
   *   if (ageInDays < 30) return 25;
   *   if (ageInDays < 90) return 10;
   *   return 0;
   * ══════════════════════════════════════════════════════════
   */
  private async checkNewlyRegisteredDomain(_fromAddr: string): Promise<number> {
    // ─── STUB ─────────────────────────────────────────────────────────────────
    // Remove this return and implement above when WHOIS API key is available
    return 0;
    // ─────────────────────────────────────────────────────────────────────────
  }

  // ─── Rule 28: URL Reputation ─────────────────────────────────────────────────
  /**
   * Checks extracted URLs against threat intelligence databases.
   *
   * STATUS: STUB — returns 0 until API key is configured.
   *
   * ══════════════════════════════════════════════════════════
   * HOW TO IMPLEMENT:
   *
   * Option A — VirusTotal (free tier: 4 req/min)
   *   const urlId = Buffer.from(url).toString('base64').replace(/=/g, '');
   *   const res   = await fetch(
   *     `https://www.virustotal.com/api/v3/urls/${urlId}`,
   *     { headers: { 'x-apikey': process.env.VIRUSTOTAL_API_KEY } }
   *   );
   *   const data       = await res.json();
   *   const malicious  = data.data?.attributes?.last_analysis_stats?.malicious ?? 0;
   *   if (malicious > 3)  return 50;
   *   if (malicious > 0)  return 25;
   *
   * Option B — Google Safe Browsing (free, higher rate limit)
   *   const res = await fetch(
   *     `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GSB_API_KEY}`,
   *     { method: 'POST', body: JSON.stringify({ threatInfo: { threatEntries: [{ url }] } }) }
   *   );
   *   const data = await res.json();
   *   if (data.matches?.length > 0) return 50;
   *
   * ══════════════════════════════════════════════════════════
   */
  private async checkUrlReputation(
    _email: EmailContentForClassification,
  ): Promise<number> {
    // ─── STUB ─────────────────────────────────────────────────────────────────
    // Remove this return and implement above when API key is available
    return 0;
    // ─────────────────────────────────────────────────────────────────────────
  }
}
