// ─────────────────────────────────────────────────────────────────────────────
// security/intelligence/intelligence-cache.service.ts
//
// IntelligenceCacheService — Redis-backed threat intelligence cache.
//
// Caches four threat signal categories:
//   1. File Hash Reputation  (SHA-256 → malware verdict)
//   2. URL Reputation        (url string → threat score)
//   3. IP Reputation         (IPv4/IPv6 → reputation verdict)
//   4. Domain Reputation     (domain string → reputation verdict)
//
// Architecture note:
//   This service is INTENTIONALLY decoupled from its callers via an interface.
//   The static analysis logic (IP/domain/URL pattern matching) lives here
//   so that when you move to an external gRPC reputation server, you only
//   need to:
//     1. Remove the static analysis methods from this class
//     2. Inject a gRPC client and call the remote service
//     3. Keep the cache layer intact (same TTLs, same key format)
//
// Cache key format:
//   intel:hash:<sha256>
//   intel:url:<sha256 of url string>   ← hash the key to avoid Redis key injection
//   intel:ip:<ip>
//   intel:domain:<domain>
//
// TTLs:
//   Hash hits   → 24h  (file hashes change rarely)
//   URL hits     → 1h  (URLs go stale faster)
//   IP hits      → 6h
//   Domain hits  → 12h
//   Negative (unknown) → 15min  (re-check soon if no verdict yet)
// ─────────────────────────────────────────────────────────────────────────────

import {
  Injectable,
  Logger,
  OnModuleInit,
  Optional,
  Inject,
  forwardRef,
} from '@nestjs/common';
import { createHash } from 'crypto';
import { ThreatFeedsService } from './threat-feeds.service';

// ─── Cache entry shapes ───────────────────────────────────────────────────────

export interface HashIntelResult {
  sha256: string;
  verdict: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  score: number;   // 0-100
  family?: string;   // malware family name if known
  source: 'cache' | 'local' | 'grpc';
  cachedAt: number;   // unix ms
}

export interface UrlIntelResult {
  url: string;
  verdict: 'clean' | 'suspicious' | 'malicious' | 'unknown';
  score: number;  // 0-100
  reason: string;
  source: 'cache' | 'local' | 'grpc';
  cachedAt: number;
}

export interface IpIntelResult {
  ip: string;
  reputation: 'good' | 'bad' | 'neutral' | 'unknown';
  score: number;  // 0-100, higher = worse
  isProxy: boolean;
  isTor: boolean;
  country?: string;
  source: 'cache' | 'local' | 'grpc';
  cachedAt: number;
}

export interface DomainIntelResult {
  domain: string;
  reputation: 'good' | 'bad' | 'neutral' | 'unknown';
  score: number;  // 0-100
  isNewlyReg: boolean; // less than 30 days old (heuristic)
  isSuspiciousTld: boolean;
  isDisposable: boolean;
  source: 'cache' | 'local' | 'grpc';
  cachedAt: number;
}

// ─── Redis client interface (thin — only what we need) ───────────────────────
// We accept the ioredis client via injection token 'REDIS_CLIENT'
// This keeps the class testable without a real Redis instance.
export interface RedisClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, exMode: 'EX', ttlSeconds: number): Promise<unknown>;
  del(key: string): Promise<number>;
  keys(pattern: string): Promise<string[]>;
}

// ─── TTLs (seconds) ───────────────────────────────────────────────────────────
const TTL = {
  HASH_MALICIOUS: 86400,  // 24h
  HASH_CLEAN: 43200,  // 12h
  HASH_UNKNOWN: 900,   // 15min
  URL_MALICIOUS: 3600,  // 1h
  URL_CLEAN: 3600,  // 1h
  URL_UNKNOWN: 900,  // 15min
  IP_BAD: 21600,  // 6h
  IP_GOOD: 21600,  // 6h
  IP_UNKNOWN: 900,  // 15min
  DOMAIN_BAD: 43200,  // 12h
  DOMAIN_GOOD: 43200,  // 12h
  DOMAIN_UNKNOWN: 900,  // 15min
} as const;

// ─── Known disposable email domains (subset — extend as needed) ──────────────
const DISPOSABLE_DOMAINS = new Set([
  'mailinator.com', 'guerrillamail.com', 'temp-mail.org', 'throwaway.email',
  'sharklasers.com', 'guerrillamailblock.com', 'grr.la', 'guerrillamail.info',
  'yopmail.com', 'yopmail.fr', 'cool.fr.nf', 'jetable.fr.nf', 'nospam.ze.tc',
  'nomail.xl.cx', 'mega.zik.dj', 'speed.1s.fr', 'courriel.fr.nf', 'moncourrier.fr.nf',
  'dispostable.com', 'trashmail.com', 'trashmail.me', 'trashmail.net',
  'fakeinbox.com', 'spamgourmet.com', 'spamgourmet.net', 'spamgourmet.org',
  'spam4.me', 'bccto.me', 'chacuo.net', 'discard.email', 'discardmail.com',
  'emailondeck.com', 'filzmail.com', 'getairmail.com', 'hidemail.de',
  'mailnull.com', 'maildrop.cc', 'mailnesia.com', 'mailnull.com',
  'nowmymail.com', 'objectmail.com', 'ownmail.net', 'peeweemail.com',
  'tempinbox.com', 'tempr.email', 'trashmail.at', 'trashmail.io',
]);

// ─── Suspicious TLDs ─────────────────────────────────────────────────────────
const SUSPICIOUS_TLDS = new Set([
  '.tk', '.ml', '.ga', '.cf', '.gq', '.xyz', '.top', '.click',
  '.download', '.loan', '.work', '.party', '.gdn', '.racing',
  '.date', '.review', '.trade', '.webcam', '.win', '.faith',
]);

// ─── Known malicious hash patterns (example — in production query VirusTotal) ─
// SHA-256 prefixes of known malware families (first 8 hex chars)
// This is illustrative — real production should use a threat feed
const KNOWN_MALICIOUS_HASH_PREFIXES = new Set([
  '44d88612', // EICAR test file
  'cf8bd9dfda', // common macro malware prefix
]);

// ─── URL shortener domains ────────────────────────────────────────────────────
const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
  'adf.ly', 'j.mp', 'tr.im', 'cutt.ly', 'rebrand.ly', 'shorturl.at',
  'tiny.cc', 'snip.ly', 'bl.ink', 'shorte.st', 'bc.vc', 'clck.ru',
]);

// ─────────────────────────────────────────────────────────────────────────────

@Injectable()
export class IntelligenceCacheService implements OnModuleInit {
  private readonly logger = new Logger(IntelligenceCacheService.name);
  private redisAvailable = false;
  private readonly memoryCache = new Map<string, { value: string; expiresAt: number }>();
  private readonly MEMORY_TTL_MS = 5 * 60 * 1000; // 5 دقايق (أقل من Redis TTL)

  constructor(

    // Optional — works without Redis (in-memory fallback for tests)
    @Optional() @Inject('REDIS_CLIENT')
    private readonly redis: RedisClient | null,
    // Optional — real-time threat feeds (AbuseIPDB, URLhaus, PhishTank)
    @Optional()
    private readonly threatFeeds: ThreatFeedsService | null,
  ) { }

  onModuleInit(): void {
    if (!this.redis) {
      this.logger.warn(
        'IntelligenceCacheService: No Redis client injected. ' +
        'Cache disabled — all lookups will use local analysis only. ' +
        'Inject REDIS_CLIENT token to enable caching.',
      );
    } else {
      this.redisAvailable = true;
      this.logger.log('IntelligenceCacheService: Redis cache active.');
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // FILE HASH INTELLIGENCE
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * lookupFileHash() — check if a SHA-256 hash is known malicious.
   *
   * 1. Check Redis cache
   * 2. If miss → run local heuristic (EICAR, known prefix set)
   * 3. Cache the result
   *
   * Extension point: replace step 2 with a gRPC call to VirusTotal proxy
   * or your own threat feed server. The cache logic stays identical.
   */
  async lookupFileHash(sha256: string): Promise<HashIntelResult> {
    const key = `intel:hash:${sha256}`;

    // ── Cache hit ─────────────────────────────────────────────────────────────
    const cached = await this.cacheGet<HashIntelResult>(key);
    if (cached) return { ...cached, source: 'cache' };

    // ── Local analysis ────────────────────────────────────────────────────────
    const result = this.analyzeHashLocally(sha256);

    // ── Write to cache ────────────────────────────────────────────────────────
    const ttl = result.verdict === 'malicious' ? TTL.HASH_MALICIOUS
      : result.verdict === 'clean' ? TTL.HASH_CLEAN
        : TTL.HASH_UNKNOWN;
    await this.cacheSet(key, result, ttl);

    return result;
  }

  /**
   * setFileHashResult() — write an external verdict (e.g. from gRPC) into cache.
   * Call this after you get a result from your malware analysis server.
   */
  async setFileHashResult(result: HashIntelResult): Promise<void> {
    const key = `intel:hash:${result.sha256}`;
    const ttl = result.verdict === 'malicious' ? TTL.HASH_MALICIOUS
      : result.verdict === 'clean' ? TTL.HASH_CLEAN
        : TTL.HASH_UNKNOWN;
    await this.cacheSet(key, { ...result, source: 'grpc', cachedAt: Date.now() }, ttl);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // URL INTELLIGENCE
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * lookupUrl() — analyze a URL for threat signals.
   *
   * Caches using SHA-256 of the URL string to avoid Redis key injection issues
   * (URLs can contain arbitrary characters).
   */
  async lookupUrl(url: string): Promise<UrlIntelResult> {
    const urlHash = createHash('sha256').update(url).digest('hex');
    const key = `intel:url:${urlHash}`;

    const cached = await this.cacheGet<UrlIntelResult>(key);
    if (cached) return { ...cached, source: 'cache' };

    // ── Local static analysis ─────────────────────────────────────────────────
    let result = this.analyzeUrlLocally(url);

    // ── Real-time threat feeds (only if static didn't already flag as malicious) ─
    if (this.threatFeeds && result.verdict !== 'malicious') {
      try {
        const feedResult = await this.threatFeeds.lookupUrl(url);
        if (feedResult.isBlacklisted) {
          result = {
            url,
            verdict: 'malicious',
            score: feedResult.score,
            reason: `Blacklisted by: ${feedResult.sources.join(', ')}${feedResult.threat ? ` — ${feedResult.threat}` : ''}`,
            source: 'grpc',
            cachedAt: Date.now(),
          };
        }
      } catch (err) {
        this.logger.warn(`ThreatFeeds URL lookup failed (non-fatal): ${err}`);
      }
    }

    const ttl = result.verdict === 'malicious' ? TTL.URL_MALICIOUS
      : result.verdict === 'clean' ? TTL.URL_CLEAN
        : TTL.URL_UNKNOWN;
    await this.cacheSet(key, result, ttl);

    return result;
  }

  /**
   * lookupUrls() — batch URL lookup. More efficient than N individual calls.
   */
  async lookupUrls(urls: string[]): Promise<Map<string, UrlIntelResult>> {
    const results = new Map<string, UrlIntelResult>();
    // Could be parallelized further with Promise.all on cache reads
    await Promise.all(
      urls.slice(0, 50).map(async url => {
        results.set(url, await this.lookupUrl(url));
      }),
    );
    return results;
  }

  /**
   * setUrlResult() — write external verdict (gRPC) into cache.
   */
  async setUrlResult(url: string, result: UrlIntelResult): Promise<void> {
    const urlHash = createHash('sha256').update(url).digest('hex');
    const key = `intel:url:${urlHash}`;
    const ttl = result.verdict === 'malicious' ? TTL.URL_MALICIOUS
      : result.verdict === 'clean' ? TTL.URL_CLEAN
        : TTL.URL_UNKNOWN;
    await this.cacheSet(key, { ...result, source: 'grpc', cachedAt: Date.now() }, ttl);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // IP REPUTATION
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * lookupIp() — check IP reputation.
   *
   * Local analysis: RFC1918 private ranges are trusted, known Tor/proxy
   * patterns get flagged. In production: replace local analysis with
   * AbuseIPDB or your internal threat feed gRPC call.
   */
  async lookupIp(ip: string): Promise<IpIntelResult> {
    if (!ip || !this.isValidIp(ip)) {
      return this.unknownIpResult(ip);
    }

    const key = `intel:ip:${ip}`;
    const cached = await this.cacheGet<IpIntelResult>(key);
    if (cached) return { ...cached, source: 'cache' };

    // ── Local analysis first ──────────────────────────────────────────────────
    let result = this.analyzeIpLocally(ip);

    // ── Real-time feed (AbuseIPDB) — only for public IPs with unknown reputation ─
    if (this.threatFeeds && result.reputation === 'unknown') {
      try {
        const feedResult = await this.threatFeeds.lookupIp(ip);
        if (feedResult.reputation !== 'unknown') {
          result = {
            ip,
            reputation: feedResult.reputation === 'bad' ? 'bad' : 'neutral',
            score: feedResult.score,
            isProxy: feedResult.details.isProxy,
            isTor: feedResult.details.isTor,
            country: feedResult.details.country,
            source: 'grpc',
            cachedAt: Date.now(),
          };
        }
      } catch (err) {
        this.logger.warn(`ThreatFeeds IP lookup failed (non-fatal): ${err}`);
      }
    }

    const ttl = result.reputation === 'bad' ? TTL.IP_BAD
      : result.reputation === 'good' ? TTL.IP_GOOD
        : TTL.IP_UNKNOWN;
    await this.cacheSet(key, result, ttl);

    return result;
  }

  /**
   * setIpResult() — write external verdict into cache.
   */
  async setIpResult(ip: string, result: IpIntelResult): Promise<void> {
    const key = `intel:ip:${ip}`;
    const ttl = result.reputation === 'bad' ? TTL.IP_BAD
      : result.reputation === 'good' ? TTL.IP_GOOD
        : TTL.IP_UNKNOWN;
    await this.cacheSet(key, { ...result, source: 'grpc', cachedAt: Date.now() }, ttl);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // DOMAIN REPUTATION
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * lookupDomain() — check domain reputation.
   *
   * Checks:
   *   - Disposable email provider list
   *   - Suspicious TLD
   *   - Domain age heuristics (newly registered pattern detection)
   *   - Homoglyph detection
   */
  async lookupDomain(domain: string): Promise<DomainIntelResult> {
    const normalizedDomain = domain.toLowerCase().trim();
    if (!normalizedDomain) {
      return this.unknownDomainResult(domain);
    }

    const key = `intel:domain:${normalizedDomain}`;
    const cached = await this.cacheGet<DomainIntelResult>(key);
    if (cached) return { ...cached, source: 'cache' };

    const result = this.analyzeDomainLocally(normalizedDomain);

    const ttl = result.reputation === 'bad' ? TTL.DOMAIN_BAD
      : result.reputation === 'good' ? TTL.DOMAIN_GOOD
        : TTL.DOMAIN_UNKNOWN;
    await this.cacheSet(key, result, ttl);

    return result;
  }

  /**
   * setDomainResult() — write external verdict into cache.
   */
  async setDomainResult(domain: string, result: DomainIntelResult): Promise<void> {
    const key = `intel:domain:${domain.toLowerCase()}`;
    const ttl = result.reputation === 'bad' ? TTL.DOMAIN_BAD
      : result.reputation === 'good' ? TTL.DOMAIN_GOOD
        : TTL.DOMAIN_UNKNOWN;
    await this.cacheSet(key, { ...result, source: 'grpc', cachedAt: Date.now() }, ttl);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CACHE MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * invalidate() — remove a specific entry from cache.
   * Useful after a false positive is reported.
   */
  async invalidate(type: 'hash' | 'url' | 'ip' | 'domain', value: string): Promise<void> {
    if (!this.redis || !this.redisAvailable) return;
    try {
      let key: string;
      if (type === 'url') {
        const urlHash = createHash('sha256').update(value).digest('hex');
        key = `intel:url:${urlHash}`;
      } else if (type === 'hash') {
        key = `intel:hash:${value}`;
      } else {
        key = `intel:${type}:${value.toLowerCase()}`;
      }
      await this.redis.del(key);
      this.logger.log(`Cache invalidated: ${key}`);
    } catch (err) {
      this.logger.warn(`Cache invalidation failed for ${type}:${value} — ${err}`);
    }
  }

  /**
   * getCacheStats() — returns counts of cached entries by type.
   * Used by the admin controller for monitoring.
   */
  async getCacheStats(): Promise<Record<string, number>> {
    // ── Count memory cache entries ────────────────────────
    const now = Date.now();
    let memHash = 0, memUrl = 0, memIp = 0, memDomain = 0;

    for (const [key, entry] of this.memoryCache.entries()) {
      if (entry.expiresAt < now) continue; // skip expired
      if (key.startsWith('intel:hash:')) memHash++;
      else if (key.startsWith('intel:url:')) memUrl++;
      else if (key.startsWith('intel:ip:')) memIp++;
      else if (key.startsWith('intel:domain:')) memDomain++;
    }

    // ── No Redis → return memory counts ──────────────────
    if (!this.redis || !this.redisAvailable) {
      return { hash: memHash, url: memUrl, ip: memIp, domain: memDomain, redis: 0 };
    }

    try {
      const [hashKeys, urlKeys, ipKeys, domainKeys] = await Promise.all([
        this.redis.keys('intel:hash:*'),
        this.redis.keys('intel:url:*'),
        this.redis.keys('intel:ip:*'),
        this.redis.keys('intel:domain:*'),
      ]);
      return {
        hash: hashKeys.length,
        url: urlKeys.length,
        ip: ipKeys.length,
        domain: domainKeys.length,
        redis: 1,
      };
    } catch {
      return { hash: memHash, url: memUrl, ip: memIp, domain: memDomain, redis: 0 };
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // LOCAL ANALYSIS (extension points for gRPC)
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * analyzeHashLocally() — heuristic hash reputation without external services.
   *
   * ─── TO REPLACE WITH gRPC ───────────────────────────────────────────────
   *   Replace this method body with:
   *     const response = await firstValueFrom(
   *       this.grpcClient.CheckHash({ sha256 })
   *     );
   *     return this.mapGrpcHashResponse(sha256, response);
   * ────────────────────────────────────────────────────────────────────────
   */
  analyzeHashLocally(sha256: string): HashIntelResult {
    const lower = sha256.toLowerCase();

    // EICAR test file (well-known SHA-256)
    if (lower === '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f') {
      return {
        sha256, verdict: 'malicious', score: 100,
        family: 'EICAR', source: 'local', cachedAt: Date.now(),
      };
    }

    // Check known malicious hash prefix set
    for (const prefix of KNOWN_MALICIOUS_HASH_PREFIXES) {
      if (lower.startsWith(prefix)) {
        return {
          sha256, verdict: 'malicious', score: 85,
          family: 'known_malware', source: 'local', cachedAt: Date.now(),
        };
      }
    }

    // Unknown hash — can't determine without external feed
    return {
      sha256, verdict: 'unknown', score: 0,
      source: 'local', cachedAt: Date.now(),
    };
  }

  /**
   * analyzeUrlLocally() — static URL threat analysis.
   *
   * ─── TO REPLACE WITH gRPC ───────────────────────────────────────────────
   *   Augment or replace this method with a gRPC call:
   *     const response = await firstValueFrom(
   *       this.grpcClient.AnalyzeUrl({ url })
   *     );
   *   Keep the local analysis as a fallback when gRPC is unavailable.
   * ────────────────────────────────────────────────────────────────────────
   */
  analyzeUrlLocally(url: string): UrlIntelResult {
    const reasons: string[] = [];
    let score = 0;

    // IP-based URL
    if (/https?:\/\/(\d{1,3}\.){3}\d{1,3}/.test(url)) {
      score += 25; reasons.push('IP-based URL');
    }

    let hostname = '';
    try {
      hostname = new URL(url).hostname.toLowerCase();
    } catch {
      return { url, verdict: 'suspicious', score: 20, reason: 'Malformed URL', source: 'local', cachedAt: Date.now() };
    }

    // URL shortener
    if (URL_SHORTENERS.has(hostname)) {
      score += 20; reasons.push('URL shortener');
    }

    // Suspicious TLD
    if ([...SUSPICIOUS_TLDS].some(tld => hostname.endsWith(tld))) {
      score += 20; reasons.push('Suspicious TLD');
    }

    // Punycode / IDN spoofing (xn-- encoded domains)
    if (/\bxn--/i.test(hostname)) {
      score += 35; reasons.push('Punycode IDN domain (potential homoglyph spoof)');
    }

    // Homoglyph in domain (direct Unicode chars)
    if (this.hasHomoglyph(hostname)) {
      score += 30; reasons.push('Homoglyph domain');
    }

    // Base64-encoded URL payload
    if (this.hasBase64Payload(url)) {
      score += 25; reasons.push('Base64-encoded payload');
    }

    // Open redirect
    if (/[?&](url|redirect|return|next|goto|dest)=/i.test(url)) {
      score += 15; reasons.push('Open redirect parameter');
    }

    // Data URI
    if (/^data:[^;]+;base64,/i.test(url)) {
      score += 35; reasons.push('Data URI');
    }

    const finalScore = Math.min(100, score);
    const verdict: UrlIntelResult['verdict'] = finalScore >= 70 ? 'malicious'
      : finalScore >= 40 ? 'suspicious'
        : finalScore > 0 ? 'suspicious'
          : 'clean';

    return {
      url, verdict, score: finalScore,
      reason: reasons.join(', ') || 'No threat signals',
      source: 'local', cachedAt: Date.now(),
    };
  }

  /**
   * analyzeIpLocally() — static IP reputation analysis.
   *
   * ─── TO REPLACE WITH gRPC ───────────────────────────────────────────────
   *   Replace this method body with:
   *     const response = await firstValueFrom(
   *       this.grpcClient.CheckIp({ ip })
   *     );
   *     return this.mapGrpcIpResponse(ip, response);
   * ────────────────────────────────────────────────────────────────────────
   */
  analyzeIpLocally(ip: string): IpIntelResult {
    // Private/loopback IPs are trusted
    if (this.isPrivateIp(ip)) {
      return {
        ip, reputation: 'good', score: 0,
        isProxy: false, isTor: false,
        source: 'local', cachedAt: Date.now(),
      };
    }

    // IPv6 local
    if (ip === '::1' || ip.startsWith('fe80:')) {
      return {
        ip, reputation: 'good', score: 0,
        isProxy: false, isTor: false,
        source: 'local', cachedAt: Date.now(),
      };
    }

    // Without external intel, we can't determine real reputation
    return {
      ip, reputation: 'unknown', score: 0,
      isProxy: false, isTor: false,
      source: 'local', cachedAt: Date.now(),
    };
  }

  /**
   * analyzeDomainLocally() — static domain reputation analysis.
   *
   * ─── TO REPLACE WITH gRPC ───────────────────────────────────────────────
   *   Replace this method body with:
   *     const response = await firstValueFrom(
   *       this.grpcClient.CheckDomain({ domain })
   *     );
   *     return this.mapGrpcDomainResponse(domain, response);
   * ────────────────────────────────────────────────────────────────────────
   */
  analyzeDomainLocally(domain: string): DomainIntelResult {
    const isDisposable = DISPOSABLE_DOMAINS.has(domain);
    const isSuspiciousTld = [...SUSPICIOUS_TLDS].some(tld => domain.endsWith(tld));
    const hasHomoglyph = this.hasHomoglyph(domain);

    // Newly registered pattern: very short numeric-heavy or random-char domains
    const isNewlyRegPattern = this.looksNewlyRegistered(domain);

    let score = 0;
    if (isDisposable) score += 40;
    if (isSuspiciousTld) score += 30;
    if (hasHomoglyph) score += 35;
    if (isNewlyRegPattern) score += 20;

    score = Math.min(100, score);

    const reputation: DomainIntelResult['reputation'] =
      score >= 40 ? 'bad'
        : score >= 20 ? 'neutral'
          : 'unknown';  // can't say "good" without an external whitelist

    return {
      domain, reputation, score,
      isNewlyReg: isNewlyRegPattern,
      isSuspiciousTld,
      isDisposable,
      source: 'local', cachedAt: Date.now(),
    };
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // PRIVATE HELPERS
  // ═══════════════════════════════════════════════════════════════════════════

  private async cacheGet<T>(key: string): Promise<T | null> {
    // ── Try Redis first ───────────────────────────────────
    if (this.redis && this.redisAvailable) {
      try {
        const raw = await this.redis.get(key);
        if (raw) return JSON.parse(raw) as T;
      } catch {
        // Redis error → fall through to memory
      }
    }

    // ── Fallback: in-memory cache ─────────────────────────
    const entry = this.memoryCache.get(key);
    if (!entry) return null;
    if (Date.now() > entry.expiresAt) {
      this.memoryCache.delete(key);
      return null;
    }
    return JSON.parse(entry.value) as T;
  }

  private async cacheSet<T>(key: string, value: T, ttlSeconds: number): Promise<void> {
    const serialized = JSON.stringify(value);

    // ── Write to Redis if available ───────────────────────
    if (this.redis && this.redisAvailable) {
      try {
        await this.redis.set(key, serialized, 'EX', ttlSeconds);
      } catch (err) {
        this.logger.warn(`Cache write failed for ${key}: ${err}`);
      }
    }

    // ── Always write to memory cache ─────────────────────
    // (TTL = min(requested, MEMORY_TTL_MS) عشان memory محدودة)
    this.memoryCache.set(key, {
      value: serialized,
      expiresAt: Date.now() + Math.min(ttlSeconds * 1000, this.MEMORY_TTL_MS),
    });
  }

  private isValidIp(ip: string): boolean {
    // IPv4
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)) {
      return ip.split('.').every(n => parseInt(n) <= 255);
    }
    // IPv6 (simplified)
    return /^[0-9a-fA-F:]+$/.test(ip) && ip.includes(':');
  }

  private isPrivateIp(ip: string): boolean {
    return (
      ip.startsWith('10.') ||
      ip.startsWith('192.168.') ||
      ip.startsWith('172.16.') ||
      ip.startsWith('172.17.') ||
      ip.startsWith('172.18.') ||
      ip.startsWith('172.19.') ||
      ip.startsWith('172.2') ||
      ip.startsWith('172.3') ||
      ip.startsWith('127.') ||
      ip === '0.0.0.0'
    );
  }

  private hasHomoglyph(str: string): boolean {
    const homoglyphs = ['а', 'е', 'о', 'р', 'с', 'у', 'х', 'ο', 'ι'];
    return homoglyphs.some(g => str.includes(g));
  }

  private hasBase64Payload(url: string): boolean {
    if (/^data:[^;]+;base64,/i.test(url)) return true;
    const match = url.match(/[?&][^=]+=([A-Za-z0-9+/]{20,}={0,2})(?:&|$)/);
    if (!match) return false;
    try {
      const decoded = Buffer.from(match[1], 'base64').toString('utf-8');
      return /^https?:\/\//i.test(decoded);
    } catch { return false; }
  }

  // FIX-5: looksNewlyRegistered — أضفنا length threshold وentropy check
  // المشكلة القديمة: 'btn.example.com' كان يُعتبر DGA (consonant-heavy)
  // الحل: SLD لازم > 7 chars، ولازم يحتوي أرقام، وconsonant ratio > 0.78
  private looksNewlyRegistered(domain: string): boolean {
    const parts = domain.split('.');
    const sld = parts[parts.length - 2] ?? '';

    // FIX-5a: Short legitimate names (btn، api، cdn، dev) aren't DGA
    if (sld.length < 8) return false;

    const consonants = (sld.match(/[bcdfghjklmnpqrstvwxyz]/gi) ?? []).length;
    const total = sld.length;
    const hasNumbers = /\d/.test(sld);

    // FIX-5b: لازم يحتوي أرقام — DGA domains عادةً بتشيل numbers
    if (!hasNumbers) return false;

    const consonantRatio = consonants / total;

    // FIX-5c: رفعنا الـ threshold من 0.75 لـ 0.78 لتقليل false positives
    // FIX-5d: أضفنا Shannon entropy check — DGA names بتكون high entropy
    const entropyHigh = this.shannonEntropy(sld) > 3.5;

    return consonantRatio > 0.78 && entropyHigh;
  }

  // FIX-5: Shannon entropy — DGA domains have high character entropy
  private shannonEntropy(str: string): number {
    const freq = new Map<string, number>();
    for (const c of str) freq.set(c, (freq.get(c) ?? 0) + 1);
    let entropy = 0;
    for (const count of freq.values()) {
      const p = count / str.length;
      entropy -= p * Math.log2(p);
    }
    return entropy;
  }

  private unknownIpResult(ip: string): IpIntelResult {
    return { ip, reputation: 'unknown', score: 0, isProxy: false, isTor: false, source: 'local', cachedAt: Date.now() };
  }

  private unknownDomainResult(domain: string): DomainIntelResult {
    return { domain, reputation: 'unknown', score: 0, isNewlyReg: false, isSuspiciousTld: false, isDisposable: false, source: 'local', cachedAt: Date.now() };
  }
}
