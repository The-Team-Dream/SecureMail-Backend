// ─────────────────────────────────────────────────────────────────────────────
// security/tests/security-hardening.spec.ts
// ─────────────────────────────────────────────────────────────────────────────

import { IntelligenceCacheService } from '../intelligence/intelligence-cache.service';
import {
  parseUrlDomain,
  detectPunycodeSpoof,
  detectSubdomainImpersonation,
} from '../pipeline/5-url-analysis/url-analysis.service';
import { normalizeText } from '../pipeline/4-behavior/behavior.service';

// ─── Redis Mock ───────────────────────────────────────────────────────────────

function makeMockRedis() {
  const store = new Map<string, { value: string; expiresAt?: number }>();

  return {
    get: jest.fn(async (key: string): Promise<string | null> => {
      const entry = store.get(key);
      if (!entry) return null;
      if (entry.expiresAt && Date.now() > entry.expiresAt) { store.delete(key); return null; }
      return entry.value;
    }),
    set: jest.fn(async (key: string, value: string, _exMode?: string, ttlSecs?: number) => {
      store.set(key, { value, expiresAt: ttlSecs ? Date.now() + ttlSecs * 1000 : undefined });
      return 'OK';
    }),
    del: jest.fn(async (key: string) => { const e = store.has(key); store.delete(key); return e ? 1 : 0; }),
    keys: jest.fn(async (pattern: string) => {
      const prefix = pattern.replace('*', '');
      return [...store.keys()].filter(k => k.startsWith(prefix));
    }),
    _store:      store,
    _clearStore: () => store.clear(),
  };
}

function makeService(redis: any = null): IntelligenceCacheService {
  const svc = new IntelligenceCacheService(redis, null);
  svc.onModuleInit();
  return svc;
}

// ─── Intelligence Cache — URL Lookup ─────────────────────────────────────────

describe('IntelligenceCacheService — URL lookup', () => {

  beforeEach(() => jest.clearAllMocks());

  it('✅ Unknown URL → verdict=unknown, score=0', async () => {
    const result = await makeService().lookupUrl('https://totally-unknown-site.com/path');
    expect(result.verdict).toBe('unknown');
    expect(result.threatScore).toBe(0);
    expect(result.source).toBe('local');
  });

  it('✅ Same URL looked up twice → second call returns cache hit', async () => {
    const redis = makeMockRedis();
    const svc   = makeService(redis);

    await svc.lookupUrl('https://bit.ly/test');
    const setCount = redis.set.mock.calls.length;

    await svc.lookupUrl('https://bit.ly/test');
    expect(redis.set.mock.calls.length).toBe(setCount); // no extra set on cache hit
  });

  it('✅ setUrlResult then lookup → returns cached result', async () => {
    const redis = makeMockRedis();
    const svc   = makeService(redis);

    await svc.setUrlResult('https://evil.com/phish', {
      url:        'https://evil.com/phish',
      verdict:    'malicious',
      threatScore: 90,
      threat:     'confirmed phishing',
      source:     'grpc',
      cachedAt:   Date.now(),
    });

    const result = await svc.lookupUrl('https://evil.com/phish');
    expect(result.source).toBe('cache');
    expect(result.verdict).toBe('malicious');
    expect(result.threatScore).toBe(90);
  });

  it('✅ Cache key is SHA-256 hash, not raw URL (injection prevention)', async () => {
    const redis = makeMockRedis();
    const svc   = makeService(redis);

    const maliciousUrl = 'https://evil.com/?inject=intel:domain:google.com';
    await svc.lookupUrl(maliciousUrl);

    const keys = redis.set.mock.calls.map((c: any[]) => c[0] as string);
    expect(keys.length).toBeGreaterThan(0);
    expect(keys[0]).toMatch(/^intel:url:[a-f0-9]{64}$/);
    expect(keys[0]).not.toContain('intel:domain:google.com');
  });

  it('✅ Two different URLs produce different cache keys', async () => {
    const redis = makeMockRedis();
    const svc   = makeService(redis);

    await svc.lookupUrl('https://bit.ly/evil1');
    await svc.lookupUrl('https://bit.ly/evil2');

    const keys = redis.set.mock.calls.map((c: any[]) => c[0]);
    expect(keys[0]).not.toBe(keys[1]);
  });
});

// ─── Intelligence Cache — IP Lookup ──────────────────────────────────────────

describe('IntelligenceCacheService — IP lookup', () => {

  it('✅ Valid IP format → returns result without crash', async () => {
    const result = await makeService().lookupIp('8.8.8.8');
    expect(result.ip).toBe('8.8.8.8');
    expect(result.ipReputationScore).toBeDefined();
  });

  it('✅ Invalid IP → returns unknown result (no crash)', async () => {
    const result = await makeService().lookupIp('not-an-ip');
    expect(result.ipReputationScore).toBe(0);
    expect(result.isIpBlacklisted).toBe(false);
  });
});

// ─── Intelligence Cache — Domain Lookup ──────────────────────────────────────

describe('IntelligenceCacheService — Domain lookup', () => {

  it('✅ Unknown domain → domainReputationScore=0', async () => {
    const result = await makeService().lookupDomain('totally-unknown-domain.com');
    expect(result.domain).toBe('totally-unknown-domain.com');
    expect(result.domainReputationScore).toBe(0);
  });

  it('✅ Domain cache: second lookup returns cache hit', async () => {
    const redis = makeMockRedis();
    const svc   = makeService(redis);

    await svc.lookupDomain('trashmail.com');
    const setCount = redis.set.mock.calls.length;
    await svc.lookupDomain('trashmail.com');
    expect(redis.set.mock.calls.length).toBe(setCount);
  });

  it('✅ Empty string domain → returns fallback (no crash)', async () => {
    const result = await makeService().lookupDomain('');
    expect(result.domainReputationScore).toBe(0);
  });
});

// ─── Cache Stats ──────────────────────────────────────────────────────────────

describe('IntelligenceCacheService — getCacheStats', () => {

  it('✅ No Redis → returns memory cache stats', async () => {
    const svc   = makeService(null);
    const stats = await svc.getCacheStats();
    expect(stats).toHaveProperty('url');
    expect(stats).toHaveProperty('ip');
    expect(stats).toHaveProperty('domain');
    expect(stats.redis).toBe(0);
  });

  it('✅ With Redis → returns redis key counts', async () => {
    const redis = makeMockRedis();
    const svc   = makeService(redis);

    await svc.lookupUrl('https://bit.ly/test');
    await svc.lookupIp('1.2.3.4');

    const stats = await svc.getCacheStats();
    expect(stats.redis).toBe(1);
    expect(stats.url + stats.ip + stats.domain).toBeGreaterThan(0);
  });
});

// ─── URL Domain Parsing ───────────────────────────────────────────────────────

describe('URL Domain Parsing — Security Tests', () => {

  it('✅ Simple domain: google.com', () => {
    const p = parseUrlDomain('https://google.com');
    expect(p!.domain).toBe('google.com');
    expect(p!.domainBase).toBe('google');
    expect(p!.publicSuffix).toBe('com');
    expect(p!.subdomain).toBeNull();
  });

  it('✅ Subdomain: www.google.com', () => {
    const p = parseUrlDomain('https://www.google.com/search');
    expect(p!.domain).toBe('google.com');
    expect(p!.subdomain).toBe('www');
  });

  it('✅ Double TLD: evil.co.uk', () => {
    const p = parseUrlDomain('https://evil.co.uk/phish');
    expect(p!.domain).toBe('evil.co.uk');
    expect(p!.publicSuffix).toBe('co.uk');
  });

  it('✅ Subdomain attack: paypal.com.evil.ru → registered domain is evil.ru', () => {
    const p = parseUrlDomain('http://paypal.com.evil.ru/signin');
    expect(p!.domain).toBe('evil.ru');
    expect(p!.subdomain).toContain('paypal');
  });

  it('✅ Punycode spoof: xn--pple-43d.com detected', () => {
    expect(detectPunycodeSpoof('xn--pple-43d.com')).toBe(true);
  });

  it('✅ Cyrillic homoglyph domain detected', () => {
    expect(detectPunycodeSpoof('аррӏе.com')).toBe(true);
  });

  it('✅ Legitimate domain not flagged as spoof', () => {
    expect(detectPunycodeSpoof('apple.com')).toBe(false);
    expect(detectPunycodeSpoof('microsoft.com')).toBe(false);
  });

  it('✅ Brand in subdomain detected: paypal.evil.com', () => {
    const p = parseUrlDomain('http://paypal.evil.com/login');
    const { isSpoof, spoofedBrand } = detectSubdomainImpersonation(p!);
    expect(isSpoof).toBe(true);
    expect(spoofedBrand).toBe('paypal');
  });

  it('✅ Legitimate mail.google.com NOT flagged', () => {
    const p = parseUrlDomain('https://mail.google.com/mail');
    expect(p!.domain).toBe('google.com');
    const { isSpoof } = detectSubdomainImpersonation(p!);
    expect(isSpoof).toBe(false);
  });

  it('✅ amazon.com.attacker.net → detected', () => {
    const p = parseUrlDomain('http://amazon.com.attacker.net/order');
    const { isSpoof, spoofedBrand } = detectSubdomainImpersonation(p!);
    expect(isSpoof).toBe(true);
    expect(spoofedBrand).toBe('amazon');
  });
});

// ─── BEC Obfuscation: normalizeText ──────────────────────────────────────────

describe('BEC Obfuscation — normalizeText', () => {

  it('✅ Numeric substitution: w1re transfer → wire transfer', () => {
    expect(normalizeText('w1re transfer request')).toContain('wire transfer');
  });

  it('✅ Turkish dotless i: wıre transfer normalized', () => {
    expect(normalizeText('wıre transfer request')).toContain('wire transfer');
  });

  it('✅ Punctuation: wire-transfer → wire transfer', () => {
    expect(normalizeText('wire-transfer today')).toContain('wire transfer');
  });

  it('✅ Dot: wire.transfer → wire transfer', () => {
    expect(normalizeText('wire.transfer now')).toContain('wire transfer');
  });

  it('✅ Cyrillic homoglyphs normalized', () => {
    expect(normalizeText('your аccount suspended')).toContain('account');
  });

  it('✅ Leet: g1ft c4rd → gift card', () => {
    expect(normalizeText('buy g1ft c4rd')).toContain('gift card');
  });

  it('✅ Normal text not mangled', () => {
    const out = normalizeText('Hello, please review the attached invoice.');
    expect(out).toContain('invoice');
    expect(out).toContain('hello');
  });

  it('✅ Empty string → empty string (no crash)', () => {
    expect(normalizeText('')).toBe('');
  });
});
