// ─────────────────────────────────────────────────────────────────────────────
// security/tests/url-domain-parsing.spec.ts
//
// PART 1 + 2 + 3: URL Domain Parsing Security Tests
//
// Tests the robust domain parser that replaces naive hostname extraction.
// Covers all attack scenarios from the security brief.
// ─────────────────────────────────────────────────────────────────────────────

import {
  parseUrlDomain,
  detectPunycodeSpoof,
  detectSubdomainImpersonation,
} from '../pipeline/url-analysis/url-analysis.service';

describe('PART 1 — Robust Domain Parsing (tldts-compatible)', () => {

  describe('Basic registered domain extraction', () => {
    it('✅ Simple domain: google.com', () => {
      const p = parseUrlDomain('https://google.com');
      expect(p!.domain).toBe('google.com');
      expect(p!.domainBase).toBe('google');
      expect(p!.publicSuffix).toBe('com');
      expect(p!.subdomain).toBeNull()
    });

    it('✅ Subdomain: www.google.com', () => {
      const p = parseUrlDomain('https://www.google.com/search');
      expect(p!.domain).toBe('google.com');
      expect(p!.subdomain).toBe('www');
    });

    it('✅ Deep subdomain: a.b.c.example.com', () => {
      const p = parseUrlDomain('https://a.b.c.example.com/path');
      expect(p!.domain).toBe('example.com');
      expect(p!.subdomain).toBe('a.b.c');
    });
  });

  describe('Double TLD handling (co.uk, com.au)', () => {
    it('✅ co.uk: evil.co.uk → domain="evil.co.uk"', () => {
      const p = parseUrlDomain('https://evil.co.uk/phish');
      expect(p!.domain).toBe('evil.co.uk');
      expect(p!.publicSuffix).toBe('co.uk');
    });

    it('✅ com.au: attack.com.au → domain="attack.com.au"', () => {
      const p = parseUrlDomain('https://attack.com.au/login');
      expect(p!.domain).toBe('attack.com.au');
    });

    it('✅ subdomain on co.uk: login.evil.co.uk → subdomain="login"', () => {
      const p = parseUrlDomain('https://login.evil.co.uk/auth');
      expect(p!.domain).toBe('evil.co.uk');
      expect(p!.subdomain).toBe('login');
    });
  });

  describe('CRITICAL: Subdomain attack patterns', () => {
    // This is the key security test — naive parsers fail here
    it('✅ paypal.com.evil.ru → registered domain is evil.ru', () => {
      const p = parseUrlDomain('http://paypal.com.evil.ru/signin');
      expect(p!.domain).toBe('evil.ru');        // ← registered domain (attacker)
      expect(p!.subdomain).toContain('paypal'); // ← brand in subdomain
    });

    it('✅ login.microsoft.com.secure-login.ru → registered domain is secure-login.ru', () => {
      const p = parseUrlDomain('https://login.microsoft.com.secure-login.ru/auth');
      expect(p!.domain).toBe('secure-login.ru');
      expect(p!.subdomain).toContain('microsoft');
    });

    it('✅ verify.apple.com.malicious.xyz → registered domain is malicious.xyz', () => {
      const p = parseUrlDomain('https://verify.apple.com.malicious.xyz/id');
      expect(p!.domain).toBe('malicious.xyz');
    });
  });
});

describe('PART 2 — Punycode & Homoglyph Detection', () => {

  describe('Punycode/ACE encoded domains', () => {
    it('✅ xn--pple-43d.com (punycode for аррӏе.com) → detected', () => {
      expect(detectPunycodeSpoof('xn--pple-43d.com')).toBe(true);
    });

    it('✅ login.xn--micrsoft-9db.com → detected (subdomain has xn--)', () => {
      expect(detectPunycodeSpoof('login.xn--micrsoft-9db.com')).toBe(true);
    });

    it('✅ xn--e1awd7f.com (another IDN) → detected', () => {
      expect(detectPunycodeSpoof('xn--e1awd7f.com')).toBe(true);
    });
  });

  describe('Direct Unicode homoglyphs', () => {
    it('✅ аррӏе.com (all Cyrillic) → detected', () => {
      // а=U+0430 р=U+0440 ӏ=U+04C1 е=U+0435
      expect(detectPunycodeSpoof('аррӏе.com')).toBe(true);
    });

    it('✅ paypal.cоm (Cyrillic о) → detected', () => {
      expect(detectPunycodeSpoof('paypal.cоm')).toBe(true);
    });

    it('✅ micrοsοft.com (Greek ο) → detected', () => {
      expect(detectPunycodeSpoof('micrοsοft.com')).toBe(true);
    });
  });

  describe('Clean domains → NOT flagged', () => {
    const cleanDomains = [
      'google.com', 'microsoft.com', 'apple.com',
      'paypal.com', 'amazon.co.uk', 'github.com',
      'secure.bank.com', 'mail.example.org',
    ];

    it.each(cleanDomains)('✅ %s → clean (no false positive)', (domain) => {
      expect(detectPunycodeSpoof(domain)).toBe(false);
    });
  });
});

describe('PART 3 — Subdomain Impersonation Detection', () => {

  it('✅ paypal in subdomain of evil.ru → spoofed', () => {
    const parsed = parseUrlDomain('http://paypal.com.evil.ru')!;
    const { isSpoof, spoofedBrand } = detectSubdomainImpersonation(parsed);
    expect(isSpoof).toBe(true);
    expect(spoofedBrand).toBe('paypal');
  });

  it('✅ microsoft in subdomain → spoofed', () => {
    const parsed = parseUrlDomain('https://microsoft.com.phish.net')!;
    const { isSpoof } = detectSubdomainImpersonation(parsed);
    expect(isSpoof).toBe(true);
  });

  it('✅ google in subdomain → spoofed', () => {
    const parsed = parseUrlDomain('http://accounts.google.com.login-now.ru')!;
    const { isSpoof, spoofedBrand } = detectSubdomainImpersonation(parsed);
    expect(isSpoof).toBe(true);
    expect(spoofedBrand).toBe('google');
  });

  it('✅ Legitimate www.paypal.com → NOT spoofed', () => {
    const parsed = parseUrlDomain('https://www.paypal.com')!;
    const { isSpoof } = detectSubdomainImpersonation(parsed);
    expect(isSpoof).toBe(false);
  });

  it('✅ Legitimate accounts.google.com → NOT spoofed', () => {
    const parsed = parseUrlDomain('https://accounts.google.com/signin')!;
    const { isSpoof } = detectSubdomainImpersonation(parsed);
    expect(isSpoof).toBe(false);
  });

  it('✅ apple.com.attacker.io → detected as apple impersonation', () => {
    const parsed = parseUrlDomain('https://apple.com.attacker.io/id/login')!;
    const { isSpoof, spoofedBrand } = detectSubdomainImpersonation(parsed);
    expect(isSpoof).toBe(true);
    expect(spoofedBrand).toBe('apple');
  });
});
