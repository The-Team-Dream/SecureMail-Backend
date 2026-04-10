import {
  Injectable,
  Logger,
  OnModuleInit,
  Optional,
  Inject,
} from '@nestjs/common';
import { createHash } from 'crypto';
import { ThreatFeedsService } from './threat-feeds.service';
import { DomainIntelResult, IpIntelResult, UrlIntelResult } from 'src/security/types';
import { DISPOSABLE_DOMAINS, SUSPICIOUS_TLDS, TTL } from 'src/security/constants';

// ─── Cache entry shapes ───────────────────────────────────────────────────────
export interface RedisClient {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, exMode: 'EX', ttlSeconds: number): Promise<unknown>;
  del(key: string): Promise<number>;
  keys(pattern: string): Promise<string[]>;
}


@Injectable()
export class IntelligenceCacheService implements OnModuleInit {
  private readonly logger = new Logger(IntelligenceCacheService.name);
  private redisAvailable = false;
  private readonly memoryCache = new Map<string, { value: string; expiresAt: number }>();
  private readonly MEMORY_TTL_MS = 5 * 60 * 1000;

  constructor(
    @Optional() @Inject('REDIS_CLIENT')
    private readonly redis: RedisClient | null,
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


  // URL Analysis
  async lookupUrls(urls: string[]): Promise<Map<string, UrlIntelResult>> {
    const results = new Map<string, UrlIntelResult>();
    await Promise.all(
      urls.slice(0, 50).map(async url => {
        results.set(url, await this.lookupUrl(url));
      }),
    );
    return results;
  }
  async lookupUrl(url: string): Promise<UrlIntelResult> {
    const urlHash = createHash('sha256').update(url).digest('hex');
    const key = `intel:url:${urlHash}`;
    const cached = await this.cacheGet<UrlIntelResult>(key);
    if (cached) return { ...cached, source: 'cache' };
    let result: UrlIntelResult = this.unknownUrlResult(url);
    if (this.threatFeeds) {
      try {
        const feedResult = await this.threatFeeds.lookupUrl(url);
        if (feedResult.isBlacklisted) {
          result = {
            url,
            verdict: 'malicious',
            threatScore: feedResult.threatScore,
            threat: `Blacklisted by: ${(feedResult.sources ?? []).join(', ')}${feedResult.threat ? ` — ${feedResult.threat}` : ''}`,
            source: 'local',
            cachedAt: Date.now(),
          };
        }
      } catch (err) {
        this.logger.warn(`ThreatFeeds URL lookup failed (non-fatal): ${err}`);
      }
    }
    const ttl = result.verdict === 'malicious' ? TTL.URL_KNOWN : TTL.URL_UNKNOWN;
    await this.cacheSet(key, result, ttl);
    return result;
  }


  async setUrlResult(url: string, result: UrlIntelResult): Promise<void> {
    const urlHash = createHash('sha256').update(url).digest('hex');
    const key = `intel:url:${urlHash}`;
    const ttl = result.verdict === 'malicious' ? TTL.URL_KNOWN : TTL.URL_UNKNOWN;
    await this.cacheSet(key, { ...result, source: 'grpc', cachedAt: Date.now() }, ttl);
  }

  // IP Analysis
  async lookupIp(ip: string): Promise<IpIntelResult> {
    if (!this.isValidIp(ip)) {
      return this.unknownIpResult(ip);
    }
    const key = `intel:ip:${ip}`;
    const cached = await this.cacheGet<IpIntelResult>(key);
    if (cached) {
      return { ...cached, source: 'cache' };
    }
    let result: IpIntelResult = this.unknownIpResult(ip);
    if (this.threatFeeds) {
      try {
        const feedResult = await this.threatFeeds.lookupIp(ip);
        if (feedResult) {
          result = {
            ip,
            ipReputationScore: feedResult.ipReputationScore ?? 0,
            isIpBlacklisted: feedResult.isIpBlacklisted ?? false,
            ipCountry: feedResult.ipCountry ?? 'unknown',
            isIpDatacenter: feedResult.isIpDatacenter ?? false,
            isIpTor: feedResult.isIpTor ?? false,
            isIpProxy: feedResult.isIpProxy ?? false,
            source: 'local',
            cachedAt: Date.now(),
          };
        }
      } catch (err) {
        this.logger.warn(`ThreatFeeds IP lookup failed (non-fatal): ${err}`);
      }
    }
    const ttl = result.isIpBlacklisted ? TTL.IP_KNOWN : TTL.IP_UNKNOWN;
    await this.cacheSet(key, result, ttl);
    return result;
  }

  // Domain Analysis
  async lookupDomain(domain: string): Promise<DomainIntelResult> {
    const normalizedDomain = domain.toLowerCase().trim();
    if (!normalizedDomain) {
      return this.unknownDomainResult(domain);
    }
    const key = `intel:domain:${normalizedDomain}`;
    const cached = await this.cacheGet<DomainIntelResult>(key);
    if (cached) return { ...cached, source: 'cache' };
    let result: DomainIntelResult = this.unknownDomainResult(normalizedDomain);
    if (this.threatFeeds) {
      try {
        const feedResult = await this.threatFeeds.lookupDomain(normalizedDomain);
        if (feedResult) {
          result = {
            domain: normalizedDomain,
            domainReputationScore: feedResult.domainReputationScore ?? 0,
            domainBlacklisted: feedResult.domainBlacklisted ?? false,
            domainAgeDays: feedResult.domainAgeDays,
            newlyRegisteredDomain: feedResult.newlyRegisteredDomain ?? false,
            domainRegistrar: feedResult.domainRegistrar ?? 'unknown',
            whoisHidden: feedResult.whoisHidden ?? false,
            mxRecordsExist: feedResult.mxRecordsExist ?? false,
            source: 'local',
            cachedAt: Date.now(),
          };
        }
      } catch (err) {
        this.logger.warn(`ThreatFeeds domain lookup failed (non-fatal): ${err}`);
      }
    }
    const ttl =
      result.domainBlacklisted ? TTL.DOMAIN_KNOWN : TTL.DOMAIN_UNKNOWN;

    await this.cacheSet(key, result, ttl);

    return result;
  }

  async invalidate(type: 'url' | 'ip' | 'domain', value: string): Promise<void> {
    if (!this.redis || !this.redisAvailable) return;
    try {
      let key: string;
      if (type === 'url') {
        const urlHash = createHash('sha256').update(value).digest('hex');
        key = `intel:url:${urlHash}`;
      } else {
        key = `intel:${type}:${value.toLowerCase()}`;
      }
      await this.redis.del(key);
      this.logger.log(`Cache invalidated: ${key}`);
    } catch (err) {
      this.logger.warn(`Cache invalidation failed for ${type}:${value} — ${err}`);
    }
  }

  async getCacheStats(): Promise<Record<string, number>> {
    // ── Count memory cache entries ────────────────────────
    const now = Date.now();
    let memUrl = 0, memIp = 0, memDomain = 0;

    for (const [key, entry] of this.memoryCache.entries()) {
      if (entry.expiresAt < now) continue; // 
      if (key.startsWith('intel:url:')) memUrl++;
      else if (key.startsWith('intel:ip:')) memIp++;
      else if (key.startsWith('intel:domain:')) memDomain++;
    }

    // ── No Redis → return memory counts ──────────────────
    if (!this.redis || !this.redisAvailable) {
      return { url: memUrl, ip: memIp, domain: memDomain, redis: 0 };
    }

    try {
      const [urlKeys, ipKeys, domainKeys] = await Promise.all([
        this.redis.keys('intel:url:*'),
        this.redis.keys('intel:ip:*'),
        this.redis.keys('intel:domain:*'),
      ]);
      return {
        url: urlKeys.length,
        ip: ipKeys.length,
        domain: domainKeys.length,
        redis: 1,
      };
    } catch {
      return { url: memUrl, ip: memIp, domain: memDomain, redis: 0 };
    }
  }

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

  private unknownUrlResult(url: string): UrlIntelResult {
    return { url, threatScore: 0, verdict: 'unknown', source: 'local', cachedAt: Date.now() };
  }
  private unknownIpResult(ip: string): IpIntelResult {
    return { ip, ipReputationScore: 0, isIpBlacklisted: false, source: 'local', cachedAt: Date.now() };
  }
  private unknownDomainResult(domain: string): DomainIntelResult {
    return { domain, domainReputationScore: 0, domainBlacklisted: false, source: 'local', cachedAt: Date.now() };
  }
}