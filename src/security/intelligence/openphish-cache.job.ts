// ─────────────────────────────────────────────────────────────────────────────
// security/intelligence/openphish-cache.job.ts
//
// OpenPhish Feed Cache Job
//
// OpenPhish (https://openphish.com/feed.txt) بيوفر plain text feed
// بدون API key — سطر لكل URL مشبوه.
//
// المشكلة لو قلنا fetch لكل URL: بطيء + unreliable
// الحل: نحمّل الـ feed كل ساعة ونخزنه في Redis SET
//   → Query بعدين: SISMEMBER openphish:urls <url> — فوري بدون network
//
// ─── Integration ──────────────────────────────────────────────────────────────
// في ThreatFeedsService.checkUrlInOpenPhish() بدل الـ placeholder:
//
//   const isMember = await this.redis.sismember('openphish:urls', url);
//   return { url, isListed: isMember === 1, source: 'local' };
//
// ─── Schedule ─────────────────────────────────────────────────────────────────
// Cron: كل ساعة (OpenPhish بيتحدث كل ساعة تقريباً)
//
// ─── Setup ────────────────────────────────────────────────────────────────────
//   npm install @nestjs/schedule
//   In AppModule: ScheduleModule.forRoot()
//   In IntelligenceModule: add OpenPhishCacheJob to providers
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable, Logger, Optional, Inject } from '@nestjs/common';
import { Cron, CronExpression }                 from '@nestjs/schedule';

// Redis client interface (subset of ioredis)
interface RedisWithSets {
  get(key: string): Promise<string | null>;
  set(key: string, value: string, exMode: 'EX', ttlSeconds: number): Promise<unknown>;
  del(key: string): Promise<number>;
  keys(pattern: string): Promise<string[]>;
  sadd(key: string, ...members: string[]): Promise<number>;
  sismember(key: string, member: string): Promise<number>;
  scard(key: string): Promise<number>;
  expire(key: string, seconds: number): Promise<number>;
}

const OPENPHISH_FEED_URL   = 'https://openphish.com/feed.txt';
const REDIS_KEY            = 'openphish:urls';
const FEED_TTL_SECONDS     = 7200;  // 2h (slightly above 1h refresh to avoid gap)
const MAX_URLS_PER_FEED    = 50000; // safety cap
const BATCH_SIZE           = 1000;  // Redis SADD batch size

@Injectable()
export class OpenPhishCacheJob {
  private readonly logger = new Logger(OpenPhishCacheJob.name);
  private lastFetchCount = 0;
  private lastFetchAt: Date | null = null;

  constructor(
    @Optional() @Inject('REDIS_CLIENT')
    private readonly redis: RedisWithSets | null,
  ) {
    if (!this.redis) {
      this.logger.warn('OpenPhishCacheJob: No Redis client — feed caching disabled.');
    }
  }

  // ─── Scheduled Job: Every Hour ─────────────────────────────────────────────
  @Cron(CronExpression.EVERY_HOUR)
  async refreshFeed(): Promise<void> {
    if (!this.redis) return;

    try {
      this.logger.log('OpenPhishCacheJob: Fetching feed from openphish.com...');

      const urls = await this.downloadFeed();
      if (urls.length === 0) {
        this.logger.warn('OpenPhishCacheJob: Feed returned 0 URLs — skipping update');
        return;
      }

      await this.storeFeed(urls);
      this.lastFetchCount = urls.length;
      this.lastFetchAt    = new Date();

      this.logger.log(`OpenPhishCacheJob: Feed updated — ${urls.length} URLs cached in Redis`);

    } catch (err) {
      this.logger.error(`OpenPhishCacheJob: Feed refresh failed — ${err}`);
    }
  }

  // ─── Public API ────────────────────────────────────────────────────────────

  /**
   * isPhishing() — check if a URL is in the OpenPhish feed.
   * O(1) Redis SET lookup — no network call.
   */
  async isPhishing(url: string): Promise<boolean> {
    if (!this.redis) return false;
    try {
      const result = await this.redis.sismember(REDIS_KEY, url);
      return result === 1;
    } catch {
      return false;
    }
  }

  /**
   * getStats() — returns feed stats for monitoring.
   */
  async getStats(): Promise<{ count: number; lastFetchAt: Date | null; redisAvailable: boolean }> {
    if (!this.redis) return { count: 0, lastFetchAt: null, redisAvailable: false };
    try {
      const count = await this.redis.scard(REDIS_KEY);
      return { count, lastFetchAt: this.lastFetchAt, redisAvailable: true };
    } catch {
      return { count: 0, lastFetchAt: this.lastFetchAt, redisAvailable: false };
    }
  }

  // ─── Private: Download feed ────────────────────────────────────────────────
  private async downloadFeed(): Promise<string[]> {
    const response = await fetch(OPENPHISH_FEED_URL, {
      headers: { 'User-Agent': 'SecureMail-ThreatIntel/1.0' },
      signal:  AbortSignal.timeout(15000), // 15s timeout for feed download
    });

    if (!response.ok) {
      throw new Error(`OpenPhish returned HTTP ${response.status}`);
    }

    const text = await response.text();

    return text
      .split('\n')
      .map(line => line.trim())
      .filter(line => line.startsWith('http://') || line.startsWith('https://'))
      .slice(0, MAX_URLS_PER_FEED);
  }

  // ─── Private: Store feed in Redis SET ─────────────────────────────────────
  private async storeFeed(urls: string[]): Promise<void> {
    if (!this.redis) return;

    // Delete old set first to avoid stale URLs accumulating
    await this.redis.del(REDIS_KEY);

    // SADD in batches to avoid large Redis commands
    for (let i = 0; i < urls.length; i += BATCH_SIZE) {
      const batch = urls.slice(i, i + BATCH_SIZE);
      await (this.redis as any).sadd(REDIS_KEY, ...batch);
    }

    // Set TTL on the SET key
    await this.redis.expire(REDIS_KEY, FEED_TTL_SECONDS);
  }
}
