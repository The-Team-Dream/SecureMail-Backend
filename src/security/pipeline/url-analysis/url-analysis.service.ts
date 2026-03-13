// ─────────────────────────────────────────────────────────────────────────────
// security/pipeline/url-analysis/url-analysis.service.ts  (UPDATED v3)
//
// URL Analysis Engine — Stage 6 of the Security Pipeline.
//
// Changes from v2:
//   - Delegates URL threat analysis to IntelligenceCacheService
//   - gRPC (URL_INTEL_SERVICE) is still optional — results cached automatically
//   - Static analysis logic removed from here (moved to IntelligenceCacheService)
//   - This service now focuses on aggregation and pipeline integration
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable, Logger, Optional, Inject, OnModuleInit } from '@nestjs/common';
import type { ClientGrpc } from '@nestjs/microservices';
import { Observable, firstValueFrom } from 'rxjs';
import { ParsedEmail }           from '../email-parser/email-parser.service';
import { IntelligenceCacheService, UrlIntelResult } from '../../intelligence/intelligence-cache.service';
import { UrlSandboxService } from '../url-sandbox/url-sandbox.service';

// ─────────────────────────────────────────────────────────────────────────────
// Exported pure utility functions (used by tests + security-hardening spec)
// ─────────────────────────────────────────────────────────────────────────────

export interface ParsedUrlDomain {
  hostname:     string;
  domain:       string;   // registrable domain  e.g. "evil.ru"
  domainBase:   string;   // SLD without TLD     e.g. "evil"
  publicSuffix: string;   // TLD / ccTLD         e.g. "ru" or "co.uk"
  subdomain:    string | null;   // everything left of registrable domain
}

const DOUBLE_TLDS = new Set([
  'co.uk','co.in','co.au','co.nz','co.za','co.jp','co.kr','co.il','co.id',
  'co.th','co.ve','co.tz','co.ke','co.zw','co.bw',
  'com.au','com.br','com.ar','com.mx','com.co','com.eg','com.sa','com.pk',
  'com.ng','com.gh','com.pe','com.uy','com.bo','com.py','com.ec','com.do',
  'net.au','net.nz','org.au','org.uk','gov.uk','gov.au','edu.au','ac.uk','ac.nz',
]);

/** Parse a URL and extract domain components, handling double TLDs correctly */
export function parseUrlDomain(url: string): ParsedUrlDomain | null {
  try {
    const parsed   = new URL(url);
    const hostname = parsed.hostname.toLowerCase();
    const parts    = hostname.split('.');

    if (parts.length < 2) return null;

    // Check double TLD (e.g. co.uk, com.au)
    const lastTwo = parts.slice(-2).join('.');
    let publicSuffix: string;
    let domainIdx:    number; // index of SLD in parts array

    if (parts.length >= 3 && DOUBLE_TLDS.has(lastTwo)) {
      publicSuffix = lastTwo;                // e.g. "co.uk"
      domainIdx    = parts.length - 3;       // SLD is 3rd from end
    } else {
      publicSuffix = parts[parts.length - 1]; // e.g. "ru"
      domainIdx    = parts.length - 2;        // SLD is 2nd from end
    }

    const domainBase = parts[domainIdx];
    const domain     = parts.slice(domainIdx).join('.');
    const subdomainRaw = parts.slice(0, domainIdx).join('.');
    const subdomain    = subdomainRaw || null;  // '' → undefined

    return { hostname, domain, domainBase, publicSuffix, subdomain };
  } catch {
    return null;
  }
}

// Known brand names for subdomain impersonation detection
const BRAND_BASES = new Set([
  'paypal','google','microsoft','apple','amazon','facebook','instagram',
  'twitter','netflix','ebay','dropbox','linkedin','yahoo','outlook','gmail',
  'chase','wellsfargo','bankofamerica','citibank','hsbc',
  'fawry','instapay','cib','nbe','meeza','vodafone','orange','etisalat',
]);

/** Detect if a brand name appears as subdomain of a different attacker domain */
export function detectSubdomainImpersonation(parsed: ParsedUrlDomain): { isSpoof: boolean; spoofedBrand: string | null } {
  if (!parsed.subdomain) return { isSpoof: false, spoofedBrand: null };

  const subParts = parsed.subdomain.split('.');
  for (const part of subParts) {
    if (BRAND_BASES.has(part)) {
      // Brand is in subdomain but domain itself is NOT that brand
      if (parsed.domainBase !== part) {
        return { isSpoof: true, spoofedBrand: part };
      }
    }
  }
  return { isSpoof: false, spoofedBrand: null };
}

// Unicode ranges for Cyrillic, Greek, Latin Extended, Fullwidth
const UNICODE_HOMOGLYPH_RE = /[\u0400-\u04FF\u0370-\u03FF\u0100-\u017F\u1E00-\u1EFF\uFF01-\uFFEF]/;

/** Detect punycode (xn--) encoded IDN or direct Unicode homoglyphs in hostname */
export function detectPunycodeSpoof(hostname: string): boolean {
  // ACE-encoded IDN labels
  if (/\bxn--/i.test(hostname)) return true;
  // Direct Unicode chars that are homoglyphs
  if (UNICODE_HOMOGLYPH_RE.test(hostname)) return true;
  return false;
}

// ─── Re-export result types (used by SecurityService and ScoringService) ─────
export interface UrlThreatSignal {
  url:               string;
  isIpBased:         boolean;
  isShortened:       boolean;
  hasHomoglyphDomain: boolean;
  isSuspiciousTld:   boolean;
  isBase64Encoded:   boolean;
  hasRedirectChain:  boolean;
  reputationVerdict: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  threatScore:       number;
  reason:            string;
  source:            'cache' | 'local' | 'grpc';
}

export interface UrlAnalysisResult {
  analyzedUrls:      UrlThreatSignal[];
  totalThreatScore:  number;
  hasHighThreatUrl:  boolean;
  hasMaliciousUrl:   boolean;
  summary:           string;
}

// ─── gRPC interface (optional — results are cached) ──────────────────────────
interface UrlIntelRequest  { urls: string[]; }
interface UrlIntelResponse {
  results: Array<{ url: string; verdict: string; score: number; reason: string; }>;
}
interface UrlIntelGrpcService {
  AnalyzeUrls(req: UrlIntelRequest): Observable<UrlIntelResponse>;
}

@Injectable()
export class UrlAnalysisService implements OnModuleInit {
  private readonly logger = new Logger(UrlAnalysisService.name);
  private urlIntelClient: UrlIntelGrpcService | null = null;

  constructor(
    private readonly intel: IntelligenceCacheService,
    @Optional() private readonly sandbox: UrlSandboxService | null,
    @Optional() @Inject('URL_INTEL_SERVICE')
    private readonly client: ClientGrpc | null,
  ) {}

  onModuleInit(): void {
    if (!this.client) return;
    try {
      this.urlIntelClient = this.client.getService<UrlIntelGrpcService>('UrlIntelService');
    } catch (err) {
      this.logger.warn(`UrlAnalysisService gRPC init failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /**
   * analyze() — full URL threat analysis for an email.
   * Non-fatal: returns empty result on failure.
   */
  async analyze(email: ParsedEmail): Promise<UrlAnalysisResult> {
    try {
      
      return await this.doAnalyze(email);
    } catch (err) {
      this.logger.error('UrlAnalysisService.analyze failed', {
        emailId: email.emailId,
        error:   err instanceof Error ? err.message : String(err),
      });
      return { analyzedUrls: [], totalThreatScore: 0, hasHighThreatUrl: false, hasMaliciousUrl: false, summary: '' };
    }
  }

  private async doAnalyze(email: ParsedEmail): Promise<UrlAnalysisResult> {
    if (email.urls.length === 0) {
      return { analyzedUrls: [], totalThreatScore: 0, hasHighThreatUrl: false, hasMaliciousUrl: false, summary: 'No URLs found' };
    }

    const urls = email.urls.slice(0, 30);

    // ── If gRPC available: query it and write results to cache ─────────────────
    if (this.urlIntelClient) {
      await this.fetchAndCacheGrpcResults(urls);
    }

    // ── Now get results from cache (which may include fresh gRPC data) ─────────
    const intelMap = await this.intel.lookupUrls(urls);

    // ── Map to UrlThreatSignal format ─────────────────────────────────────────
    const signals: UrlThreatSignal[] = urls.map(url => {
      const intel = intelMap.get(url);
      return this.mapToSignal(url, intel ?? null);
    });

    // ── Aggregate ─────────────────────────────────────────────────────────────
    const maxScore      = signals.reduce((m, s) => Math.max(m, s.threatScore), 0);
    const hasMalicious  = signals.some(s => s.reputationVerdict === 'malicious' || s.threatScore >= 80);
    const hasHighThreat = signals.some(s => s.threatScore >= 50);
    const totalScore    = signals.length === 0 ? 0 :
      Math.min(100, Math.round(signals.reduce((s, u) => s + u.threatScore, 0) / signals.length));

    const summary = hasMalicious
      ? `⛔ MALICIOUS URL detected (max score=${maxScore})`
      : hasHighThreat
        ? `⚠️ Suspicious URLs (max score=${maxScore})`
        : `${signals.length} URL(s) analyzed — no high threat`;

    return { analyzedUrls: signals, totalThreatScore: totalScore, hasHighThreatUrl: hasHighThreat, hasMaliciousUrl: hasMalicious, summary };
  }

  // ─── Fetch gRPC and write to cache ─────────────────────────────────────────
  private async fetchAndCacheGrpcResults(urls: string[]): Promise<void> {
    if (!this.urlIntelClient) return;
    try {
      const response = await firstValueFrom(
        this.urlIntelClient.AnalyzeUrls({ urls }),
      );
      await Promise.all(
        (response.results ?? []).map(r =>
          this.intel.setUrlResult(r.url, {
            url:      r.url,
            verdict:  r.verdict as UrlIntelResult['verdict'],
            score:    r.score,
            reason:   r.reason,
            source:   'grpc',
            cachedAt: Date.now(),
          }),
        ),
      );
    } catch (err) {
      this.logger.warn(`URL Intel gRPC failed (non-fatal): ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // ─── Map IntelligenceCacheService result to UrlThreatSignal ────────────────
  private mapToSignal(url: string, intel: UrlIntelResult | null): UrlThreatSignal {
    if (!intel) {
      return {
        url, isIpBased: false, isShortened: false,
        hasHomoglyphDomain: false, isSuspiciousTld: false,
        isBase64Encoded: false, hasRedirectChain: false,
        reputationVerdict: 'unknown', threatScore: 0, reason: 'No analysis', source: 'local',
      };
    }

    // Parse reason string back to boolean flags (set by IntelligenceCacheService)
    const reason  = intel.reason ?? '';
    return {
      url,
      isIpBased:          reason.includes('IP-based'),
      isShortened:        reason.includes('shortener'),
      hasHomoglyphDomain: reason.includes('Homoglyph'),
      isSuspiciousTld:    reason.includes('Suspicious TLD'),
      isBase64Encoded:    reason.includes('Base64'),
      hasRedirectChain:   reason.includes('redirect'),
      reputationVerdict:  intel.verdict,
      threatScore:        intel.score,
      reason,
      source:             intel.source,
    };
  }
}
