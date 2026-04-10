import { Injectable, Logger, Optional, Inject, OnModuleInit } from '@nestjs/common';
import type { ClientGrpc } from '@nestjs/microservices';
import { Observable, firstValueFrom } from 'rxjs';
import { IntelligenceCacheService } from '../../intelligence/intelligence-cache.service';
import { ParsedEmail, ParsedUrlDomain, UrlAnalysisSignals, UrlIntelResult, UrlThreatSignal } from 'src/security/types';
import { SUSPICIOUS_TLDS, URL_SHORTENERS } from 'src/security/constants';

// ─────────────────────────────────────────────────────────────────────────────
// Pure utility functions — exported for tests
// ─────────────────────────────────────────────────────────────────────────────

const DOUBLE_TLDS = new Set([
  'co.uk', 'co.in', 'co.au', 'co.nz', 'co.za', 'co.jp', 'co.kr', 'co.il', 'co.id',
  'co.th', 'co.ve', 'co.tz', 'co.ke', 'co.zw', 'co.bw',
  'com.au', 'com.br', 'com.ar', 'com.mx', 'com.co', 'com.eg', 'com.sa', 'com.pk',
  'com.ng', 'com.gh', 'com.pe', 'com.uy', 'com.bo', 'com.py', 'com.ec', 'com.do',
  'net.au', 'net.nz', 'org.au', 'org.uk', 'gov.uk', 'gov.au', 'edu.au', 'ac.uk', 'ac.nz',
]);

/** Parse a URL into domain components, handling double TLDs correctly */
export function parseUrlDomain(url: string): ParsedUrlDomain | null {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();
    const parts = hostname.split('.');
    if (parts.length < 2) return null;

    const lastTwo = parts.slice(-2).join('.');
    let publicSuffix: string;
    let domainIdx: number;

    if (parts.length >= 3 && DOUBLE_TLDS.has(lastTwo)) {
      publicSuffix = lastTwo;
      domainIdx = parts.length - 3;
    } else {
      publicSuffix = parts[parts.length - 1];
      domainIdx = parts.length - 2;
    }

    const domainBase = parts[domainIdx];
    const domain = parts.slice(domainIdx).join('.');
    const subdomainRaw = parts.slice(0, domainIdx).join('.');
    const subdomain = subdomainRaw || null;

    return { hostname, domain, domainBase, publicSuffix, subdomain };
  } catch {
    return null;
  }
}

// Known brands for subdomain impersonation detection — includes Egyptian brands
const BRAND_BASES = new Set([
  'paypal', 'google', 'microsoft', 'apple', 'amazon', 'facebook', 'instagram',
  'twitter', 'netflix', 'ebay', 'dropbox', 'linkedin', 'yahoo', 'outlook', 'gmail',
  'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc',
  'fawry', 'instapay', 'cib', 'nbe', 'meeza', 'vodafone', 'orange', 'etisalat',
  'banquemisr', 'alexbank', 'aaib',
]);

/** Detect brand name appearing as subdomain of an attacker domain */
export function detectSubdomainImpersonation(
  parsed: ParsedUrlDomain,
): { isSpoof: boolean; spoofedBrand: string | null } {
  if (!parsed.subdomain) return { isSpoof: false, spoofedBrand: null };
  const subParts = parsed.subdomain.split('.');
  for (const part of subParts) {
    if (BRAND_BASES.has(part) && parsed.domainBase !== part) {
      return { isSpoof: true, spoofedBrand: part };
    }
  }
  return { isSpoof: false, spoofedBrand: null };
}

// Unicode ranges: Cyrillic, Greek, Latin Extended, Fullwidth
const UNICODE_HOMOGLYPH_RE = /[\u0400-\u04FF\u0370-\u03FF\u0100-\u017F\u1E00-\u1EFF\uFF01-\uFFEF]/;

/** Detect punycode (xn--) encoded IDN or Unicode homoglyphs in hostname */
export function detectPunycodeSpoof(hostname: string): boolean {
  if (/\bxn--/i.test(hostname)) return true;
  if (UNICODE_HOMOGLYPH_RE.test(hostname)) return true;
  return false;
}

// ─────────────────────────────────────────────────────────────────────────────
// gRPC interface (optional)
// ─────────────────────────────────────────────────────────────────────────────

interface UrlIntelRequest { urls: string[]; }
interface UrlIntelResponse {
  results: Array<{ url: string; verdict: string; score: number; threat: string }>;
}
interface UrlIntelGrpcService {
  AnalyzeUrls(req: UrlIntelRequest): Observable<UrlIntelResponse>;
}

// ─────────────────────────────────────────────────────────────────────────────
// UrlAnalysisService
//
// Flow per URL:
//   Layer 1 — Local Heuristics   (0ms   — always runs)
//   Layer 2 — Cache Lookup       (0ms   — Redis/memory)
//   Layer 3 — Threat Feeds       (100-500ms — VirusTotal, PhishTank, URLScan)
//   Layer 4 — gRPC Intel         (optional — enriches cache for next time)
//   Merge   — max(feedScore, heuristicScore) + weighted total
// ─────────────────────────────────────────────────────────────────────────────

@Injectable()
export class UrlAnalysisService implements OnModuleInit {
  private readonly logger = new Logger(UrlAnalysisService.name);
  private urlIntelClient: UrlIntelGrpcService | null = null;

  constructor(
    private readonly intel: IntelligenceCacheService,
    @Optional() @Inject('URL_INTEL_SERVICE')
    private readonly client: ClientGrpc | null,
  ) { }

  onModuleInit(): void {
    if (!this.client) return;
    try {
      this.urlIntelClient = this.client.getService<UrlIntelGrpcService>('UrlIntelService');
    } catch (err) {
      this.logger.warn(`UrlAnalysisService gRPC init failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  // ─── Public entry point ───────────────────────────────────────────────────

  async analyze(email: ParsedEmail): Promise<UrlAnalysisSignals> {
    try {
      return await this.doAnalyze(email);
    } catch (err) {
      this.logger.error('UrlAnalysisService.analyze failed', {
        emailId: email.emailId,
        error: err instanceof Error ? err.message : String(err),
      });
      return { analyzedUrls: [], totalThreatScore: 0, hasHighThreatUrl: false, hasMaliciousUrl: false, summary: '' };
    }
  }

  // ─── Core pipeline ────────────────────────────────────────────────────────

  private async doAnalyze(email: ParsedEmail): Promise<UrlAnalysisSignals> {
    if (email.urls.length === 0) {
      return { analyzedUrls: [], totalThreatScore: 0, hasHighThreatUrl: false, hasMaliciousUrl: false, summary: 'No URLs found' };
    }

    const urls = email.urls.slice(0, 30);

    // Layer 4: gRPC — fire and forget, enriches cache for next lookups
    // بنشغله قبل الـ cache lookup عشان لو رجع بسرعة يتحفظ في الـ cache
    if (this.urlIntelClient) {
      this.fetchAndCacheGrpcResults(urls).catch(() => null); // non-blocking
    }

    // Layer 2+3: Cache → Feeds (جوه IntelligenceCacheService)
    const intelMap = await this.intel.lookupUrls(urls);

    // Layer 1 + Merge: Heuristics + Intel → final signal per URL
    const signals: UrlThreatSignal[] = urls.map(url =>
      this.buildSignal(url, intelMap.get(url) ?? null),
    );

    return this.aggregateSignals(signals, urls.length);
  }

  // ─── Signal Builder — Layer 1 + Merge ────────────────────────────────────
  //
  // بيحسب الـ flags من الـ URL نفسه مباشرة (مش من threat text)
  // وبيعمل merge مع نتيجة الـ feeds

  private buildSignal(url: string, intel: UrlIntelResult | null): UrlThreatSignal {

    // ── Layer 1: Local Heuristics — من الـ URL مباشرة ───────────────────────
    const parsed = parseUrlDomain(url);
    const hostname = parsed?.hostname ?? '';

    const isIpBased = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    const isShortened = URL_SHORTENERS.has(hostname) ||
      URL_SHORTENERS.has(parsed?.domain ?? '');
    const hasHomoglyphDomain = detectPunycodeSpoof(hostname);
    const isSuspiciousTld = parsed
      ? SUSPICIOUS_TLDS.has(parsed.publicSuffix)
      : false;
    // Base64 obfuscation: long base64 string في الـ URL path
    const isBase64Encoded = /[A-Za-z0-9+/]{30,}={0,2}/.test(
      decodeURIComponent(url).replace(/https?:\/\/[^/]+/, ''),
    );
    // Redirect chain مخبي في الـ URL نفسه (url=http://... في الـ params)
    const hasRedirectChain = (url.match(/https?:\/\//g) ?? []).length > 1;

    // Subdomain brand impersonation
    const subdomainSpoof = parsed ? detectSubdomainImpersonation(parsed) : null;
    const isSubdomainSpoof = subdomainSpoof?.isSpoof ?? false;

    // ── Heuristic Score ───────────────────────────────────────────────────────
    let heuristicScore = 0;
    const heuristicThreats: string[] = [];

    if (isIpBased) {
      heuristicScore += 30;
      heuristicThreats.push('IP-based URL');
    }
    if (isShortened) {
      heuristicScore += 20;
      heuristicThreats.push('URL shortener detected');
    }
    if (hasHomoglyphDomain) {
      heuristicScore += 40;
      heuristicThreats.push('Punycode/Unicode homoglyph domain');
    }
    if (isSuspiciousTld) {
      heuristicScore += 25;
      heuristicThreats.push(`Suspicious TLD: .${parsed?.publicSuffix}`);
    }
    if (isBase64Encoded) {
      heuristicScore += 20;
      heuristicThreats.push('Base64 obfuscation in URL path');
    }
    if (hasRedirectChain) {
      heuristicScore += 15;
      heuristicThreats.push('Redirect chain embedded in URL');
    }
    if (isSubdomainSpoof) {
      heuristicScore += 35;
      heuristicThreats.push(`Brand impersonation via subdomain: ${subdomainSpoof!.spoofedBrand}`);
    }

    heuristicScore = Math.min(80, heuristicScore); // cap — feeds بتكمل الباقي

    // ── Merge: max(heuristic, feed) ───────────────────────────────────────────
    const feedScore = intel?.threatScore ?? 0;
    const feedVerdict = intel?.verdict ?? 'unknown';
    const feedThreat = intel?.threat ?? '';
    const feedSources = intel?.sources ?? [];

    const finalScore = Math.max(feedScore, heuristicScore);

    // الـ verdict بييجي من الـ feed لو موجود، غير كده من الـ heuristic score
    const verdict: UrlThreatSignal['verdict'] =
      feedVerdict === 'malicious' ? 'malicious' :
      finalScore >= 70 ? 'malicious' :
      feedVerdict === 'suspicious' || finalScore >= 40 ? 'suspicious' :
      finalScore > 0 ? 'suspicious' :
      'clean';

    // ادمج الـ threat descriptions
    const allThreats = [
      ...heuristicThreats,
      ...(feedThreat ? [feedThreat] : []),
    ].join(' | ');

    return {
      threatScore: finalScore,
      verdict,
      threat: allThreats || undefined,
      sources: feedSources.length ? feedSources : undefined,
      isIpBased,
      isShortened,
      hasHomoglyphDomain,
      isSuspiciousTld,
      isBase64Encoded,
      hasRedirectChain,
      isBlacklisted: feedSources.length > 0 || feedVerdict === 'malicious',
    };
  }

  // ─── Aggregation ──────────────────────────────────────────────────────────
  //
  // totalThreatScore = max×0.7 + avg×0.3
  // ده أدق من average وحده — الـ worst URL بيأثر أكتر
  //
  // hasMaliciousUrl = verdict malicious أو score>=80 مع feed confirmation
  // (مش heuristics وحدها عشان نتجنب false positives)

  private aggregateSignals(signals: UrlThreatSignal[], urlCount: number): UrlAnalysisSignals {
    if (signals.length === 0) {
      return { analyzedUrls: [], totalThreatScore: 0, hasHighThreatUrl: false, hasMaliciousUrl: false, summary: 'No URLs analyzed' };
    }

    const maxScore = signals.reduce((m, s) => Math.max(m, s.threatScore), 0);
    const avgScore = Math.round(
      signals.reduce((sum, s) => sum + s.threatScore, 0) / signals.length,
    );
    const totalThreatScore = Math.min(100, Math.round(maxScore * 0.7 + avgScore * 0.3));

    // hasMaliciousUrl = feed confirmed أو heuristic خالص >= 70
    const hasMaliciousUrl = signals.some(s =>
      s.verdict === 'malicious' ||
      (s.threatScore >= 80 && (s.sources?.length ?? 0) > 0),
    );

    const hasHighThreatUrl = signals.some(s =>
      s.threatScore >= 50 ||
      s.hasHomoglyphDomain ||
      s.isIpBased,
    );

    const maliciousCount = signals.filter(s => s.verdict === 'malicious').length;
    const suspiciousCount = signals.filter(s => s.verdict === 'suspicious').length;

    const summary = hasMaliciousUrl
      ? `${maliciousCount} malicious URL(s) detected out of ${urlCount} (max score=${maxScore})`
      : hasHighThreatUrl
        ? `${suspiciousCount} suspicious URL(s) detected out of ${urlCount} (max score=${maxScore})`
        : `${urlCount} URL(s) analyzed — no significant threat`;

    return { analyzedUrls: signals, totalThreatScore, hasHighThreatUrl, hasMaliciousUrl, summary };
  }

  // ─── gRPC: fire-and-forget cache enrichment ───────────────────────────────
  // مش blocking — بيشتغل في الخلفية ويحفظ في الـ cache للمرة الجاية

  private async fetchAndCacheGrpcResults(urls: string[]): Promise<void> {
    if (!this.urlIntelClient) return;
    try {
      const response = await firstValueFrom(
        this.urlIntelClient.AnalyzeUrls({ urls }),
      );
      await Promise.all(
        (response.results ?? []).map(r =>
          this.intel.setUrlResult(r.url, {
            url: r.url,
            verdict: r.verdict as UrlIntelResult['verdict'],
            threatScore: r.score,
            threat: r.threat,
            source: 'grpc',
            cachedAt: Date.now(),
          }),
        ),
      );
    } catch (err) {
      this.logger.warn(`URL Intel gRPC failed (non-fatal): ${err instanceof Error ? err.message : String(err)}`);
    }
  }
}