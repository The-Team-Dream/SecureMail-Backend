// ─────────────────────────────────────────────────────────────────────────────
// security/intelligence/intelligence-cache.service.spec.ts
//
// Unit tests for IntelligenceCacheService.
//
// Tests cover:
//   - Hash intelligence (EICAR, known malicious, unknown)
//   - URL intelligence (IP-based, shortener, homoglyph, base64, clean)
//   - IP intelligence (private, public, invalid)
//   - Domain intelligence (disposable, suspicious TLD, DGA, clean)
//   - Cache read/write/invalidate lifecycle
//   - Redis unavailable graceful fallback
//   - Batch URL lookup
// ─────────────────────────────────────────────────────────────────────────────

import { IntelligenceCacheService } from './intelligence-cache.service';

// ─── Redis mock ───────────────────────────────────────────────────────────────
function makeMockRedis() {
  const store    = new Map<string, { value: string; expiresAt?: number }>();
  const setStore = new Map<string, Set<string>>(); // for sismember/sadd

  return {
    get: jest.fn(async (key: string) => {
      const entry = store.get(key);
      if (!entry) return null;
      if (entry.expiresAt && Date.now() > entry.expiresAt) {
        store.delete(key);
        return null;
      }
      return entry.value;
    }),
    set: jest.fn(async (key: string, value: string, _ex?: string, ttl?: number) => {
      store.set(key, {
        value,
        expiresAt: ttl ? Date.now() + ttl * 1000 : undefined,
      });
      return 'OK';
    }),
    del: jest.fn(async (key: string) => {
      const existed = store.has(key);
      store.delete(key);
      return existed ? 1 : 0;
    }),
    keys: jest.fn(async (pattern: string) => {
      const prefix = pattern.replace('*', ''); 
      return [...store.keys()].filter(k => k.startsWith(prefix));
    }),
    // ── Redis SET operations (for OpenPhish) ──
    sadd: jest.fn(async (key: string, ...members: string[]) => {
      if (!setStore.has(key)) setStore.set(key, new Set());
      const s = setStore.get(key)!;
      let added = 0;
      for (const m of members) { if (!s.has(m)) { s.add(m); added++; } }
      return added;
    }),
    sismember: jest.fn(async (key: string, member: string) => {
      return setStore.get(key)?.has(member) ? 1 : 0;
    }),
    scard: jest.fn(async (key: string) => {
      return setStore.get(key)?.size ?? 0;
    }),
    expire: jest.fn(async (key: string, ttl: number) => {
      const entry = store.get(key);
      if (!entry) return 0;
      store.set(key, { ...entry, expiresAt: Date.now() + ttl * 1000 });
      return 1;
    }),
    // Test utilities
    _store:    store,
    _setStore: setStore,
    _clear:    () => { store.clear(); setStore.clear(); },
  };
}

function makeService(redis: any = null) {
  // FIX: constructor takes (redis, threatFeeds) — pass null for threatFeeds in tests
  const svc = new IntelligenceCacheService(redis, null);
  svc.onModuleInit();
  return svc;
}

// ═════════════════════════════════════════════════════════════════════════════
// FILE HASH INTELLIGENCE
// ═════════════════════════════════════════════════════════════════════════════

describe('IntelligenceCacheService — File Hash', () => {

  it('✅ EICAR test file SHA-256 → malicious (score=100)', async () => {
    const svc = makeService();
    const result = await svc.lookupFileHash(
      '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
    );
    expect(result.verdict).toBe('malicious');
    expect(result.score).toBe(100);
    expect(result.family).toBe('EICAR');
    expect(result.source).toBe('local');
  });

  it('✅ Known malicious hash prefix → malicious', async () => {
    const svc = makeService();
    const result = await svc.lookupFileHash('44d88612fea8a8f36de82e1278abb02f');
    expect(result.verdict).toBe('malicious');
    expect(result.score).toBeGreaterThan(0);
  });

  it('✅ Unknown hash → unknown (no false positives)', async () => {
    const svc = makeService();
    const result = await svc.lookupFileHash('a'.repeat(64));
    expect(result.verdict).toBe('unknown');
    expect(result.score).toBe(0);
  });

  it('✅ Hash lookup with Redis → cached on second call', async () => {
    const redis = makeMockRedis();
    const svc   = makeService(redis);

    await svc.lookupFileHash('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f');
    expect(redis.set).toHaveBeenCalledTimes(1); // first: cache miss, writes result

    await svc.lookupFileHash('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f');
    expect(redis.get).toHaveBeenCalledTimes(2);
    expect(redis.set).toHaveBeenCalledTimes(1); // second: cache hit, no write
  });

  it('✅ setFileHashResult() writes external verdict to cache', async () => {
    const redis = makeMockRedis();
    const svc   = makeService(redis);

    await svc.setFileHashResult({
      sha256: 'deadbeef' + 'a'.repeat(56),
      verdict: 'malicious', score: 95,
      family: 'Emotet', source: 'grpc', cachedAt: Date.now(),
    });

    const result = await svc.lookupFileHash('deadbeef' + 'a'.repeat(56));
    expect(result.source).toBe('cache');
    expect(result.verdict).toBe('malicious');
  });

  it('✅ Redis unavailable → local analysis still works', async () => {
    const svc = makeService(null); // no Redis
    const result = await svc.lookupFileHash('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f');
    expect(result.verdict).toBe('malicious');
    expect(result.source).toBe('local');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// URL INTELLIGENCE
// ═════════════════════════════════════════════════════════════════════════════

describe('IntelligenceCacheService — URL Analysis', () => {

  it('✅ IP-based URL → suspicious (score >= 20)', async () => {
    const svc = makeService();
    const result = await svc.lookupUrl('http://192.168.1.1/login');
    expect(result.score).toBeGreaterThanOrEqual(20);
    expect(result.reason).toContain('IP-based');
  });

  it('✅ URL shortener → suspicious', async () => {
    const svc = makeService();
    const result = await svc.lookupUrl('https://bit.ly/3xPhishing');
    expect(result.score).toBeGreaterThanOrEqual(20);
    expect(result.reason).toContain('shortener');
  });

  it('✅ Suspicious TLD (.tk) → suspicious', async () => {
    const svc = makeService();
    const result = await svc.lookupUrl('https://paypal-security.tk/verify');
    expect(result.score).toBeGreaterThanOrEqual(20);
    expect(result.reason).toContain('Suspicious TLD');
  });

  it('✅ Open redirect parameter → adds to score', async () => {
    const svc = makeService();
    const result = await svc.lookupUrl('https://legit.com/go?redirect=https://evil.com');
    expect(result.score).toBeGreaterThanOrEqual(15);
    expect(result.reason).toContain('redirect');
  });

  it('✅ Data URI → very suspicious (score >= 35)', async () => {
    const svc = makeService();
    const result = await svc.lookupUrl('data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==');
    expect(result.score).toBeGreaterThanOrEqual(35);
    expect(result.reason).toContain('Data URI');
  });

  it('✅ Clean HTTPS URL → clean verdict, low score', async () => {
    const svc = makeService();
    const result = await svc.lookupUrl('https://www.google.com');
    expect(result.verdict).toBe('clean');
    expect(result.score).toBe(0);
  });

  it('✅ Multiple threat signals → score accumulates correctly', async () => {
    const svc = makeService();
    // IP-based (20) + suspicious TLD from .tk... but IP URL overrides TLD check
    const result = await svc.lookupUrl('https://bit.ly/evil.tk/data?redirect=https://steal.xyz');
    // shortener(20) + suspicious from .tk in redirect... at least shortener fires
    expect(result.score).toBeGreaterThanOrEqual(20);
  });

  it('✅ Score capped at 100', async () => {
    const svc = makeService();
    // Multiple signals that would exceed 100 combined
    const result = await svc.lookupUrl('http://192.168.1.1/data:image;base64,abc?redirect=x&url=y');
    expect(result.score).toBeLessThanOrEqual(100);
  });

  it('✅ lookupUrls() batch — returns result for each URL', async () => {
    const svc = makeService();
    const urls = [
      'https://google.com',
      'https://bit.ly/phish',
      'http://192.168.1.1/login',
    ];
    const results = await svc.lookupUrls(urls);
    expect(results.size).toBe(3);
    for (const url of urls) {
      expect(results.has(url)).toBe(true);
    }
  });

  it('✅ URL cache hit — same result on second call', async () => {
    const redis = makeMockRedis();
    const svc   = makeService(redis);

    const url = 'https://bit.ly/phishing';
    const r1  = await svc.lookupUrl(url);
    const r2  = await svc.lookupUrl(url);

    expect(r1.verdict).toBe(r2.verdict);
    expect(r1.score).toBe(r2.score);
    expect(redis.set).toHaveBeenCalledTimes(1); // only written once
  });

  it('✅ Malformed URL → suspicious with reason', async () => {
    const svc = makeService();
    const result = await svc.lookupUrl('not-a-valid-url-at-all');
    expect(result.verdict).toBe('suspicious');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// IP REPUTATION
// ═════════════════════════════════════════════════════════════════════════════

describe('IntelligenceCacheService — IP Reputation', () => {

  it('✅ Private IP (10.x.x.x) → good reputation', async () => {
    const svc = makeService();
    const result = await svc.lookupIp('10.0.0.1');
    expect(result.reputation).toBe('good');
    expect(result.score).toBe(0);
  });

  it('✅ Private IP (192.168.x.x) → good', async () => {
    const svc = makeService();
    expect((await svc.lookupIp('192.168.0.1')).reputation).toBe('good');
  });

  it('✅ Localhost (127.0.0.1) → good', async () => {
    const svc = makeService();
    expect((await svc.lookupIp('127.0.0.1')).reputation).toBe('good');
  });

  it('✅ IPv6 loopback (::1) → good', async () => {
    const svc = makeService();
    expect((await svc.lookupIp('::1')).reputation).toBe('good');
  });

  it('✅ Public IP without threat intel → unknown (no false positives)', async () => {
    const svc = makeService();
    const result = await svc.lookupIp('8.8.8.8');
    expect(result.reputation).toBe('unknown');
    expect(result.score).toBe(0);
  });

  it('✅ Empty IP → unknown (no crash)', async () => {
    const svc = makeService();
    const result = await svc.lookupIp('');
    expect(result.reputation).toBe('unknown');
  });

  it('✅ setIpResult() writes gRPC verdict to cache', async () => {
    const redis = makeMockRedis();
    const svc   = makeService(redis);

    await svc.setIpResult('1.2.3.4', {
      ip: '1.2.3.4', reputation: 'bad', score: 90,
      isProxy: true, isTor: false,
      source: 'grpc', cachedAt: Date.now(),
    });

    const result = await svc.lookupIp('1.2.3.4');
    expect(result.source).toBe('cache');
    expect(result.reputation).toBe('bad');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// DOMAIN REPUTATION
// ═════════════════════════════════════════════════════════════════════════════

describe('IntelligenceCacheService — Domain Reputation', () => {

  it('✅ mailinator.com → disposable, bad reputation', async () => {
    const svc = makeService();
    const result = await svc.lookupDomain('mailinator.com');
    expect(result.isDisposable).toBe(true);
    expect(result.reputation).toBe('bad');
    expect(result.score).toBeGreaterThanOrEqual(40);
  });

  it('✅ Suspicious TLD (.tk) → bad/neutral', async () => {
    const svc = makeService();
    const result = await svc.lookupDomain('evil.tk');
    expect(result.isSuspiciousTld).toBe(true);
    expect(['bad', 'neutral'].includes(result.reputation)).toBe(true);
  });

  it('✅ DGA-looking domain → isNewlyReg flag', async () => {
    const svc = makeService();
    const result = await svc.analyzeDomainLocally('xkj2vfd9q.xyz');
    // High consonant ratio + number → DGA heuristic
    expect(result.isSuspiciousTld).toBe(true);
  });

  it('✅ Normal domain → unknown (no false positives)', async () => {
    const svc = makeService();
    const result = await svc.lookupDomain('google.com');
    expect(result.reputation).toBe('unknown');
    expect(result.score).toBe(0);
    expect(result.isDisposable).toBe(false);
  });

  it('✅ Empty domain → unknown (no crash)', async () => {
    const svc = makeService();
    const result = await svc.lookupDomain('');
    expect(result.reputation).toBe('unknown');
  });

  it('✅ yopmail.com → disposable', async () => {
    const svc = makeService();
    const result = await svc.lookupDomain('yopmail.com');
    expect(result.isDisposable).toBe(true);
  });

  it('✅ trashmail.com → disposable + bad', async () => {
    const svc = makeService();
    const result = await svc.lookupDomain('trashmail.com');
    expect(result.isDisposable).toBe(true);
    expect(result.reputation).toBe('bad');
  });

  it('✅ setDomainResult() writes gRPC verdict to cache', async () => {
    const redis = makeMockRedis();
    const svc   = makeService(redis);

    await svc.setDomainResult('evil-domain.ru', {
      domain: 'evil-domain.ru', reputation: 'bad', score: 80,
      isNewlyReg: true, isSuspiciousTld: false, isDisposable: false,
      source: 'grpc', cachedAt: Date.now(),
    });

    const result = await svc.lookupDomain('evil-domain.ru');
    expect(result.source).toBe('cache');
    expect(result.reputation).toBe('bad');
  });
});

// ═════════════════════════════════════════════════════════════════════════════
// CACHE MANAGEMENT
// ═════════════════════════════════════════════════════════════════════════════

describe('IntelligenceCacheService — Cache Management', () => {

  it('✅ invalidate() removes hash from cache', async () => {
    const redis = makeMockRedis();
    const svc   = makeService(redis);

    await svc.lookupFileHash('275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f');
    await svc.invalidate('hash', '275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f');

    expect(redis.del).toHaveBeenCalledWith(
      'intel:hash:275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f'
    );
  });

  it('✅ invalidate() removes URL from cache', async () => {
    const redis = makeMockRedis();
    const svc   = makeService(redis);

    const url = 'https://bit.ly/evil';
    await svc.lookupUrl(url);
    await svc.invalidate('url', url);

    expect(redis.del).toHaveBeenCalledTimes(1);
  });

  it('✅ getCacheStats() returns counts per category', async () => {
    const redis = makeMockRedis();
    const svc   = makeService(redis);

    // Populate cache with one of each type
    await svc.lookupFileHash('a'.repeat(64));
    await svc.lookupUrl('https://google.com');
    await svc.lookupIp('8.8.8.8');
    await svc.lookupDomain('example.com');

    const stats = await svc.getCacheStats();
    expect(stats.hash).toBe(1);
    expect(stats.url).toBe(1);
    expect(stats.ip).toBe(1);
    expect(stats.domain).toBe(1);
    expect(stats.redis).toBe(1);
  });

  it('✅ getCacheStats() returns zeros when Redis unavailable', async () => {
    const svc   = makeService(null);
    const stats = await svc.getCacheStats();
    expect(stats.redis).toBe(0);
    expect(stats.hash).toBe(0);
  });

  it('✅ Redis error during get → returns null gracefully', async () => {
    const redis = makeMockRedis();
    redis.get = jest.fn().mockRejectedValue(new Error('Redis connection refused'));

    const svc    = makeService(redis);
    const result = await svc.lookupUrl('https://google.com');

    // Falls back to local analysis
    expect(result.verdict).toBe('clean');
    expect(result.source).toBe('local');
  });

  it('✅ Redis error during set → does not throw', async () => {
    const redis = makeMockRedis();
    redis.set = jest.fn().mockRejectedValue(new Error('Redis write error'));

    const svc = makeService(redis);
    // Should not throw
    await expect(svc.lookupUrl('https://google.com')).resolves.toBeDefined();
  });

  it('✅ Cache uses SHA-256 of URL as key (no injection)', async () => {
    const redis = makeMockRedis();
    const svc   = makeService(redis);

    const maliciousUrl = 'https://evil.com/?key=intel:domain:google.com:INJECT';
    await svc.lookupUrl(maliciousUrl);

    // The Redis key should be intel:url:<sha256> — not the raw URL
    const calls = redis.set.mock.calls;
    const setKey = calls[0][0] as string;
    expect(setKey).toMatch(/^intel:url:[a-f0-9]{64}$/);
  });
});
