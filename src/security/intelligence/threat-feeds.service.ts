// ─────────────────────────────────────────────────────────────────────────────
// security/intelligence/threat-feeds.service.ts
//
// Real-Time Threat Feeds Integration
//
// بدل ما نكتب الكود للـ gRPC server بتاع الـ reputation (مش موجود)،
// هنتكلم مع 3 free threat feeds مباشرة من الـ NestJS backend:
//
//   Feed 1: AbuseIPDB       — IP reputation (free: 1000 req/day)
//   Feed 2: URLhaus (Abuse) — Malicious URL blacklist (free، no key)
//   Feed 3: PhishTank       — Phishing URL database (free، needs key)
//
// ─── Architecture ─────────────────────────────────────────────────────────────
//
//   IntelligenceCacheService  ←─────────────────────────────────────
//         │                                                         │
//         ▼                                                         │
//   Cache miss?                                              Write back to cache
//         │                                                         │
//         ▼                                                         │
//   ThreatFeedsService.lookup(ip/url/domain)  ───────────────────→ │ 
//         │
//         ├─ AbuseIPDB.checkIp()
//         ├─ URLhaus.checkUrl()
//         └─ PhishTank.checkUrl()
//
// ─── في production ────────────────────────────────────────────────────────────
// الـ IntelligenceCacheService بتكون هي المدخل الوحيد:
//   local analysis → cache miss → ThreatFeedsService → cache write
//
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable, Logger, Optional, Inject } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { OpenPhishCacheJob } from './openphish-cache.job';

// ─── Result Types ──────────────────────────────────────────────────────────────

export interface FeedIpResult {
  ip:            string;
  isAbusive:     boolean;
  abuseScore:    number;        // 0-100 (AbuseIPDB confidence)
  isTor:         boolean;
  isProxy:       boolean;
  country?:      string;
  isp?:          string;
  usageType?:    string;        // 'Data Center/Web Hosting' → suspicious
  reports:       number;        // كام مرة اتبلّغ عنها
  source:        'abuseipdb' | 'local' | 'cache';
}

export interface FeedUrlResult {
  url:           string;
  isListed:      boolean;
  threat?:       string;        // 'malware_download' | 'phishing' | 'botnet_cc'
  dateAdded?:    string;        // ISO date
  tags?:         string[];
  source:        'urlhaus' | 'phishtank' | 'local' | 'cache';
}

// ─────────────────────────────────────────────────────────────────────────────

@Injectable()
export class ThreatFeedsService {
  private readonly logger = new Logger(ThreatFeedsService.name);

  // API keys من .env — optional، بيشتغل بدونهم بـ limited functionality
  private readonly abuseIpDbKey:   string | undefined;
  private readonly phishTankKey:   string | undefined;

  constructor(
    @Optional() private readonly config: ConfigService | null, 
    @Optional() private readonly openPhishJob: OpenPhishCacheJob | null,
  ) {
    this.abuseIpDbKey = config?.get<string>('ABUSEIPDB_API_KEY');
    this.phishTankKey = config?.get<string>('PHISHTANK_API_KEY');

    if (!this.abuseIpDbKey) {
      this.logger.warn('ThreatFeedsService: ABUSEIPDB_API_KEY not set — IP reputation disabled. Get free key at abuseipdb.com');
    }
    if (!this.phishTankKey) {
      this.logger.warn('ThreatFeedsService: PHISHTANK_API_KEY not set — PhishTank disabled. URLhaus still active (no key needed)');
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // FEED 1: AbuseIPDB — IP Reputation
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * checkIp() — query AbuseIPDB for IP reputation
   *
   * Free plan: 1,000 requests/day — كافي لـ ~1000 email/day
   * Paid plan: 3,000/day = ~$20/month
   *
   * API docs: https://docs.abuseipdb.com/#check-endpoint
   *
   * بيرجع:
   *   - abuseConfidenceScore: 0-100 (100 = definitely abusive)
   *   - totalReports: عدد البلاغات
   *   - isTor: هل TOR exit node
   *   - usageType: 'Data Center/Web Hosting' = مشبوه في email context
   */
  async checkIp(ip: string): Promise<FeedIpResult> {
    if (!this.abuseIpDbKey) {
      return { ip, isAbusive: false, abuseScore: 0, isTor: false, isProxy: false, reports: 0, source: 'local' };
    }

    try {
      const response = await fetch(
        `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
        {
          headers: {
            'Key':    this.abuseIpDbKey,
            'Accept': 'application/json',
          },
          signal: AbortSignal.timeout(5000),  // 5 second timeout
        },
      );

      if (!response.ok) {
        this.logger.warn(`AbuseIPDB returned ${response.status} for ${ip}`);
        return this.localIpFallback(ip);
      }

      const data: any = await response.json();
      const d         = data.data;

      return {
        ip,
        isAbusive:  d.abuseConfidenceScore >= 25,
        abuseScore: d.abuseConfidenceScore,
        isTor:      d.isTor ?? false,
        isProxy:    d.isPublicProxy ?? false,
        country:    d.countryCode,
        isp:        d.isp,
        usageType:  d.usageType,
        reports:    d.totalReports,
        source:     'abuseipdb',
      };

    } catch (err) {
      this.logger.warn(`AbuseIPDB check failed for ${ip}: ${err}`);
      return this.localIpFallback(ip);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // FEED 2: URLhaus (Abuse.ch) — Malware URL Blacklist
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * checkUrlInURLhaus() — query URLhaus for URL/domain reputation
   *
   * Free، no API key required، real-time updated
   * Contains: malware download URLs، botnet C&C، exploit kits
   *
   * API docs: https://urlhaus-api.abuse.ch/
   *
   * Note: URLhaus للـ malware URLs — مش للـ phishing (PhishTank للفيشينج)
   * عادةً بيحتوي على: .exe/.zip downloads، exploit kit landing pages
   */
  async checkUrlInURLhaus(url: string): Promise<FeedUrlResult> {
    try {
      const response = await fetch('https://urlhaus-api.abuse.ch/v1/url/', {
        method:  'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body:    `url=${encodeURIComponent(url)}`,
        signal:  AbortSignal.timeout(5000),
      });

      if (!response.ok) {
        return { url, isListed: false, source: 'urlhaus' };
      }

      const data: any = await response.json();

      // query_status: 'is_host' | 'no_results' | 'invalid_url'
      if (data.query_status === 'no_results' || data.query_status === 'invalid_url') {
        return { url, isListed: false, source: 'urlhaus' };
      }

      // url_status: 'online' | 'offline' | 'unknown'
      const isActive = data.url_status === 'online';

      return {
        url,
        isListed:  true,
        threat:    data.threat ?? 'malware_download',
        dateAdded: data.date_added,
        tags:      data.tags ?? [],
        source:    'urlhaus',
      };

    } catch (err) {
      this.logger.warn(`URLhaus check failed for ${url}: ${err}`);
      return { url, isListed: false, source: 'local' };
    }
  }

  /**
   * checkDomainInURLhaus() — check a domain (not full URL) in URLhaus
   *
   * مفيد لو URL طويل ومش عارفين نطابق بالـ URL الكامل
   */
  async checkDomainInURLhaus(domain: string): Promise<FeedUrlResult> {
    try {
      const response = await fetch('https://urlhaus-api.abuse.ch/v1/host/', {
        method:  'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body:    `host=${encodeURIComponent(domain)}`,
        signal:  AbortSignal.timeout(5000),
      });

      if (!response.ok) {
        return { url: domain, isListed: false, source: 'urlhaus' };
      }

      const data: any = await response.json();

      if (data.query_status === 'no_results') {
        return { url: domain, isListed: false, source: 'urlhaus' };
      }

      const activeUrls = (data.urls ?? []).filter((u: any) => u.url_status === 'online');

      return {
        url:      domain,
        isListed: activeUrls.length > 0,
        threat:   activeUrls[0]?.threat,
        tags:     [...new Set((data.urls ?? []).flatMap((u: any) => u.tags ?? []))] as string[],
        source:   'urlhaus',
      };

    } catch (err) {
      this.logger.warn(`URLhaus domain check failed for ${domain}: ${err}`);
      return { url: domain, isListed: false, source: 'local' };
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // FEED 3: PhishTank — Phishing URL Database
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * checkUrlInPhishTank() — check URL against PhishTank
   *
   * Free with registration، needs API key
   * Community-verified phishing URLs — أقوى من URLhaus للفيشينج
   *
   * Free limits: 40 req/min، no daily limit
   * API docs: https://www.phishtank.com/api_info.php
   *
   * بديل مجاني بدون key: OpenPhish (https://openphish.com/feed.txt)
   * بس بيكون CSV مش API — ممكن تعمله locally cached list
   */
  async checkUrlInPhishTank(url: string): Promise<FeedUrlResult> {
    if (!this.phishTankKey) {
      // Fallback: OpenPhish بدون key — لكن بيكون URL simple list، مش query API
      return this.checkUrlInOpenPhish(url);
    }

    try {
      const formData = new URLSearchParams({
        url:    url,
        format: 'json',
        app_key: this.phishTankKey,
      });

      const response = await fetch('https://checkurl.phishtank.com/checkurl/', {
        method:  'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body:    formData.toString(),
        signal:  AbortSignal.timeout(5000),
      });

      if (!response.ok) {
        return { url, isListed: false, source: 'phishtank' };
      }

      const data: any = await response.json();
      const result    = data.results;

      if (!result?.url0?.in_database) {
        return { url, isListed: false, source: 'phishtank' };
      }

      return {
        url,
        isListed: result.url0.valid === true,
        threat:   'phishing',
        dateAdded: result.url0.phish_detail_page,
        source:   'phishtank',
      };

    } catch (err) {
      this.logger.warn(`PhishTank check failed for ${url}: ${err}`);
      return { url, isListed: false, source: 'local' };
    }
  }

  /**
   * checkUrlInOpenPhish() — alternative to PhishTank، no key needed
   *
   * OpenPhish بيوفر plain text feed بدون API key
   * ─── Integration approach ──────────────────────────────────────────────────
   * الـ feed ممكن تتحمّله وتخزنه locally كل ساعة (cron job):
   *
   *   GET https://openphish.com/feed.txt
   *   → plain text، سطر لكل URL
   *   → خزّنه في Redis SET: SADD openphish:urls <url1> <url2>...
   *   → Query: SISMEMBER openphish:urls <url>
   *
   * ده أسرع وأرخص من API call لكل URL.
   */
  private async checkUrlInOpenPhish(url: string): Promise<FeedUrlResult> {
    if (!this.openPhishJob) {
      this.logger.debug('OpenPhish job not available — skipping');
      return { url, isListed: false, source: 'local' };
    }

    try {
      const isListed = await this.openPhishJob.isPhishing(url);
      return {
        url,
        isListed,
        threat:   isListed ? 'phishing' : undefined,
        source:   'local',
      };
    } catch (err) {
      this.logger.warn(`OpenPhish lookup failed for ${url}: ${err}`);
      return { url, isListed: false, source: 'local' };
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // COMBINED LOOKUP
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * lookupUrl() — check URL across all available feeds in parallel
   *
   * الاستخدام الموصى به من IntelligenceCacheService:
   *   const feedResult = await threatFeeds.lookupUrl(url);
   *   await intel.setUrlResult(url, feedResult);  // cache it
   */
  async lookupUrl(url: string): Promise<{ isBlacklisted: boolean; threat?: string; score: number; sources: string[] }> {
    const [urlhaus, phishtank] = await Promise.allSettled([
      this.checkUrlInURLhaus(url),
      this.checkUrlInPhishTank(url),
    ]);

    const urlhausResult  = urlhaus.status  === 'fulfilled' ? urlhaus.value  : null;
    const phishtankResult = phishtank.status === 'fulfilled' ? phishtank.value : null;

    const isBlacklisted = !!(urlhausResult?.isListed || phishtankResult?.isListed);
    const sources: string[] = [];
    let threat: string | undefined;
    let score = 0;

    if (urlhausResult?.isListed) {
      sources.push('urlhaus');
      threat = urlhausResult.threat;
      score  = Math.max(score, 80); // malware URL = high score
    }

    if (phishtankResult?.isListed) {
      sources.push('phishtank');
      threat = 'phishing';
      score  = Math.max(score, 90); // verified phishing = very high
    }

    return { isBlacklisted, threat, score, sources };
  }

  /**
   * lookupIp() — check IP across AbuseIPDB
   *
   * Score mapping:
   *   abuseScore >= 80 → bad (score: 100)
   *   abuseScore >= 25 → suspicious (score: 50+)
   *   isTor = true     → always add 30
   *   Data Center IP   → add 15 (في email context مشبوه)
   */
  async lookupIp(ip: string): Promise<{ reputation: 'bad' | 'neutral' | 'unknown'; score: number; details: FeedIpResult }> {
    const result = await this.checkIp(ip);

    let score = Math.round(result.abuseScore * 0.8); // scale 100→80 max from abuse score

    if (result.isTor)   score += 30;
    if (result.isProxy) score += 20;
    if (result.usageType?.toLowerCase().includes('data center')) score += 15;
    if (result.reports > 100) score += 10;

    score = Math.min(100, score);

    const reputation = score >= 50 ? 'bad' : score >= 20 ? 'neutral' : 'unknown';

    return { reputation, score, details: result };
  }

  // ─── Private Helpers ───────────────────────────────────────────────────────

  private localIpFallback(ip: string): FeedIpResult {
    return { ip, isAbusive: false, abuseScore: 0, isTor: false, isProxy: false, reports: 0, source: 'local' };
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// HOW TO INTEGRATE WITH IntelligenceCacheService
// ─────────────────────────────────────────────────────────────────────────────
//
// في intelligence-cache.service.ts أضف:
//
//   constructor(
//     @Optional() @Inject('REDIS_CLIENT') private readonly redis: RedisClient | null,
//     @Optional() private readonly threatFeeds: ThreatFeedsService | null,  // ← أضف
//   ) {}
//
//   async lookupUrl(url: string): Promise<UrlIntelResult> {
//     // Cache first
//     const cached = await this.cacheGet<UrlIntelResult>(key);
//     if (cached) return { ...cached, source: 'cache' };
//
//     // Static local analysis
//     let result = this.analyzeUrlLocally(url);
//
//     // FIX: Real-time feed lookup (NEW)
//     if (this.threatFeeds && result.verdict !== 'malicious') {
//       const feedResult = await this.threatFeeds.lookupUrl(url);
//       if (feedResult.isBlacklisted) {
//         result = {
//           url, verdict: 'malicious',
//           score: feedResult.score,
//           reason: `Blacklisted by: ${feedResult.sources.join(', ')} — ${feedResult.threat}`,
//           source: 'grpc', cachedAt: Date.now(),
//         };
//       }
//     }
//
//     await this.cacheSet(key, result, ttl);
//     return result;
//   }
//
// ─────────────────────────────────────────────────────────────────────────────
// .env SETUP
// ─────────────────────────────────────────────────────────────────────────────
//
//   # Feed 1: AbuseIPDB (free: 1000 req/day)
//   # Register at: https://www.abuseipdb.com/register
//   ABUSEIPDB_API_KEY=your_key_here
//
//   # Feed 2: URLhaus — no key needed (automatic)
//
//   # Feed 3: PhishTank (free: register at phishtank.com)
//   # OR use OpenPhish (no key, cached feed)
//   PHISHTANK_API_KEY=your_key_here
//
// ─────────────────────────────────────────────────────────────────────────────
// RATE LIMITS SUMMARY
// ─────────────────────────────────────────────────────────────────────────────
//
//   Feed          | Limit           | Cost    | Key Required
//   AbuseIPDB     | 1,000/day       | Free    | Yes (free registration)
//   URLhaus       | No limit        | Free    | No
//   PhishTank     | 40/min          | Free    | Yes (free registration)
//   OpenPhish     | Feed download   | Free    | No (cached locally)
//
// مع الـ Redis caching الموجود في IntelligenceCacheService:
//   - IP results cached 6h  → 1000 req/day يكفي ~4000 unique IPs/day
//   - URL results cached 1h → URLhaus مش ليه limit أصلاً
//
// ─────────────────────────────────────────────────────────────────────────────
