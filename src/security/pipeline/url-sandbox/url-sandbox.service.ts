// ─────────────────────────────────────────────────────────────────────────────
// security/pipeline/url-sandbox/url-sandbox.service.ts
//
// URL Sandboxing Engine
//
// ازاي URL Sandboxing بيشتغل — 3 مراحل:
//
//   Stage 1 — Static Analysis (موجود في IntelligenceCacheService)
//     Pattern matching، shortener detection، homoglyph check
//     → Fast، no network، 0ms overhead
//
//   Stage 2 — Dynamic Analysis (الملف ده)
//     Playwright headless browser: visit the URL، observe behavior
//     → Detects: redirects، credential forms، drive-by downloads، JS obfuscation
//     → ~3-8 seconds per URL
//
//   Stage 3 — Detonation (اختياري — يحتاج CAPEv2 sandbox)
//     Submit URL to CAPEv2 for full behavioral analysis
//     → Detects: exploits، drive-by-download، shellcode
//     → ~30-120 seconds — للـ high-risk URLs فقط
//
// ─── Integration في الـ Pipeline ─────────────────────────────────────────────
// يُستدعى في Stage 6 (URL Analysis) بعد IntelligenceCacheService:
//
//   if (staticResult.verdict === 'suspicious' || staticResult.score >= 40) {
//     const dynamicResult = await this.sandbox.analyze(url);
//     if (dynamicResult.verdict === 'malicious') → forward to CAPEv2
//   }
//
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable, Logger, OnModuleInit, OnModuleDestroy } from '@nestjs/common';

// ─── Result Types ──────────────────────────────────────────────────────────────

export type SandboxVerdict = 'clean' | 'suspicious' | 'malicious' | 'error' | 'timeout';

export interface DynamicAnalysisSignals {
  // Redirect chain
  redirectCount:     number;
  finalUrl:          string;          // URL بعد كل redirects
  crossOriginRedirect: boolean;       // redirect لـ domain مختلف

  // Page behavior
  hasLoginForm:      boolean;         // password field موجود
  hasPasswordField:  boolean;         // input[type=password]
  hasFakeSecurityBadge: boolean;      // "secured by" / padlock image
  downloadsFile:     boolean;         // Content-Disposition: attachment

  // JavaScript signals
  hasObfuscatedJs:   boolean;         // eval(unescape(...)) / atob patterns
  hasKeylogger:      boolean;         // addEventListener('keydown') على sensitive fields
  hasClipboardAccess: boolean;        // navigator.clipboard في context مش محتاج

  // Page content
  brandMentionedNotOwner: string[];   // brands في page title/content مش في domain
  suspiciousTitle:   boolean;         // "Login - PayPal" من non-paypal domain

  // Performance signals
  analysisDurationMs: number;
  timedOut:          boolean;
}

export interface SandboxAnalysisResult {
  url:              string;
  verdict:          SandboxVerdict;
  score:            number;           // 0-100
  signals:          DynamicAnalysisSignals;
  threatIndicators: string[];         // human-readable list
  analyzedAt:       number;           // unix ms
}

// ─── Known Brands for page content check ──────────────────────────────────────
const KNOWN_BRANDS = [
  'paypal', 'google', 'microsoft', 'amazon', 'apple', 'facebook',
  'netflix', 'instagram', 'twitter', 'linkedin', 'stripe',
  'fawry', 'instapay', 'cib', 'nbe', 'banquemisr',
];

// ─── Obfuscation patterns ─────────────────────────────────────────────────────
const OBFUSCATION_PATTERNS = [
  /eval\s*\(\s*unescape/i,
  /eval\s*\(\s*atob/i,
  /String\.fromCharCode\s*\(/i,
  /\\x[0-9a-f]{2}/i,            // hex-escaped strings in JS
  /document\.write\s*\(/i,      // dynamic DOM injection
];

// ─────────────────────────────────────────────────────────────────────────────

@Injectable()
export class UrlSandboxService implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger(UrlSandboxService.name);

  // Playwright browser instance — lazy initialized
  // نستخدم 'any' هنا عشان Playwright optional dependency
  private browser: any = null;
  private playwrightAvailable = false;

  // ─── Initialization ─────────────────────────────────────────────────────────

  async onModuleInit(): Promise<void> {
    try {
      // FIX: Use require() inside try/catch instead of dynamic import()
      // This avoids TypeScript trying to resolve 'playwright' types at compile time.
      // Playwright is an OPTIONAL runtime dependency — missing it is non-fatal.
      let playwright: any = null;
      try {
        // eslint-disable-next-line @typescript-eslint/no-var-requires
        playwright = require('playwright');
      } catch {
        // Playwright not installed — gracefully degrade to static analysis only
      }

      if (!playwright) {
        this.logger.warn(
          'UrlSandboxService: Playwright not installed. ' +
          'Dynamic URL analysis disabled — static analysis only. ' +
          'Install: npm install playwright && npx playwright install chromium',
        );
        return;
      }

      this.browser = await playwright.chromium.launch({
        headless: true,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-gpu',
          '--disable-extensions',
          '--disable-background-networking',
          '--disable-sync',
          '--disable-default-apps',
          '--mute-audio',
          '--no-first-run',
          '--safebrowsing-disable-auto-update',
        ],
      });

      this.playwrightAvailable = true;
      this.logger.log('UrlSandboxService: Playwright browser ready for URL sandboxing.');
    } catch (err) {
      this.logger.warn(`UrlSandboxService: Browser init failed — ${err}. Static analysis only.`);
    }
  }

  async onModuleDestroy(): Promise<void> {
    if (this.browser) {
      await this.browser.close().catch(() => {});
    }
  }

  // ─── Public API ─────────────────────────────────────────────────────────────

  /**
   * analyze() — Entry point for URL sandboxing.
   *
   * Strategy:
   *   1. لو Playwright مش متاح → يرجع error verdict (non-fatal)
   *   2. لو الـ URL من domain موثوق → skip (no sandbox needed)
   *   3. يفتح الـ URL في isolated browser context ويراقب الـ behavior
   *
   * @param url        - URL to analyze
   * @param timeoutMs  - Max analysis time (default: 8000ms = 8 seconds)
   */
  async analyze(url: string, timeoutMs = 8000): Promise<SandboxAnalysisResult> {
    if (!this.playwrightAvailable || !this.browser) {
      return this.errorResult(url, 'Playwright not available');
    }

    const start = Date.now();

    try {
      return await Promise.race([
        this.doAnalyze(url),
        this.timeoutResult(url, timeoutMs),
      ]);
    } catch (err) {
      this.logger.warn(`UrlSandboxService: analysis failed for ${url} — ${err}`);
      return this.errorResult(url, String(err));
    } finally {
      this.logger.debug(`UrlSandboxService: analyzed ${url} in ${Date.now() - start}ms`);
    }
  }

  /**
   * analyzeBatch() — analyze multiple URLs with concurrency limit.
   *
   * لازم نحدد الـ concurrency عشان متنفدش الـ browser memory:
   *   - max 3 concurrent URL analyses
   *   - max 30 URLs per email (consistent with url-analysis.service.ts)
   */
  async analyzeBatch(urls: string[], maxConcurrent = 3): Promise<Map<string, SandboxAnalysisResult>> {
    const results = new Map<string, SandboxAnalysisResult>();
    const chunks  = this.chunkArray(urls.slice(0, 30), maxConcurrent);

    for (const chunk of chunks) {
      const chunkResults = await Promise.allSettled(
        chunk.map(url => this.analyze(url)),
      );

      for (let i = 0; i < chunk.length; i++) {
        const r = chunkResults[i];
        results.set(
          chunk[i],
          r.status === 'fulfilled' ? r.value : this.errorResult(chunk[i], 'Promise rejected'),
        );
      }
    }

    return results;
  }

  // ─── Core Analysis ──────────────────────────────────────────────────────────

  private async doAnalyze(url: string): Promise<SandboxAnalysisResult> {
    // Isolated browser context per URL — no cookies/storage bleeding
    const context = await this.browser.newContext({
      userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      viewport:  { width: 1280, height: 720 },
      // Block images/media for speed — we only care about JS/HTML behavior
      serviceWorkers: 'block',
    });

    const page = await context.newPage();
    const signals: Partial<DynamicAnalysisSignals> = {
      redirectCount: 0, finalUrl: url, crossOriginRedirect: false,
      hasLoginForm: false, hasPasswordField: false, hasFakeSecurityBadge: false,
      downloadsFile: false, hasObfuscatedJs: false, hasKeylogger: false,
      hasClipboardAccess: false, brandMentionedNotOwner: [],
      suspiciousTitle: false, timedOut: false, analysisDurationMs: 0,
    };

    const startUrl = new URL(url);
    const redirectUrls: string[] = [];

    try {
      // ── Track redirects ───────────────────────────────────────────────────
      page.on('response', (response: any) => {
        const status = response.status();
        if (status >= 300 && status < 400) {
          signals.redirectCount = (signals.redirectCount ?? 0) + 1;
          const location = response.headers()['location'];
          if (location) {
            redirectUrls.push(location);
            try {
              const redirectDomain = new URL(location).hostname;
              if (redirectDomain !== startUrl.hostname) {
                signals.crossOriginRedirect = true;
              }
            } catch { /* relative redirect */ }
          }
        }
      });

      // ── Track file downloads ──────────────────────────────────────────────
      page.on('download', () => { signals.downloadsFile = true; });

      // ── Navigate with timeout ─────────────────────────────────────────────
      await page.goto(url, {
        waitUntil: 'domcontentloaded',
        timeout:   6000,
      });

      signals.finalUrl = page.url();

      // ── Analyze page DOM ──────────────────────────────────────────────────
      const domAnalysis = await page.evaluate((brands: string[]) => {
        const html  = document.documentElement.innerHTML.toLowerCase();
        const title = document.title.toLowerCase();

        // Password / login form
        const passwordFields = document.querySelectorAll('input[type="password"]');
        const hasPassword    = passwordFields.length > 0;
        const hasLoginForm   = !!document.querySelector('form') && hasPassword;

        // Fake security badges (common in phishing pages)
        const hasFakeSecurityBadge = /secured\s+by|ssl\s+secured|verified\s+secure|protected\s+by\s+ssl/i.test(html);

        // Brand mentions in title that don't match domain
        const hostname = window.location.hostname.toLowerCase();
        const brandMentionedNotOwner = brands.filter(brand =>
          (title.includes(brand) || html.includes(brand)) &&
          !hostname.includes(brand),
        );

        // Suspicious title (brand name in title from wrong domain)
        const suspiciousTitle = brandMentionedNotOwner.some(b => title.includes(b));

        return { hasPassword, hasLoginForm, hasFakeSecurityBadge, brandMentionedNotOwner, suspiciousTitle };
      }, KNOWN_BRANDS);

      Object.assign(signals, domAnalysis);

      // ── Analyze JavaScript ────────────────────────────────────────────────
      const jsContent = await page.evaluate(() => {
        return Array.from(document.querySelectorAll('script'))
          .map((s: any) => s.textContent || '')
          .join('\n');
      });

      signals.hasObfuscatedJs = OBFUSCATION_PATTERNS.some(p => p.test(jsContent));
      signals.hasKeylogger    = /addEventListener\s*\(\s*['"]keydown['"]/i.test(jsContent) &&
                                 /password|credential|pin|secret/i.test(jsContent);
      signals.hasClipboardAccess = /navigator\s*\.\s*clipboard/i.test(jsContent) &&
                                   !/copy|paste\s+functionality/i.test(jsContent);

    } finally {
      await context.close().catch(() => {});
    }

    const fullSignals = signals as DynamicAnalysisSignals;
    return this.scoreSignals(url, fullSignals, Date.now());
  }

  // ─── Scoring ────────────────────────────────────────────────────────────────

  private scoreSignals(url: string, signals: DynamicAnalysisSignals, startTime: number): SandboxAnalysisResult {
    let score = 0;
    const indicators: string[] = [];

    if (signals.hasLoginForm && signals.brandMentionedNotOwner.length > 0) {
      score += 45;
      indicators.push(`Credential harvesting form with brand impersonation: ${signals.brandMentionedNotOwner.join(', ')}`);
    } else if (signals.hasPasswordField) {
      score += 20;
      indicators.push('Password input field detected');
    }

    if (signals.hasObfuscatedJs) {
      score += 25;
      indicators.push('JavaScript obfuscation detected (eval/atob/fromCharCode)');
    }

    if (signals.crossOriginRedirect && signals.redirectCount >= 2) {
      score += 20;
      indicators.push(`Cross-origin redirect chain (${signals.redirectCount} hops)`);
    } else if (signals.redirectCount >= 4) {
      score += 15;
      indicators.push(`Deep redirect chain (${signals.redirectCount} hops)`);
    }

    if (signals.downloadsFile) {
      score += 30;
      indicators.push('URL triggers automatic file download');
    }

    if (signals.hasKeylogger) {
      score += 35;
      indicators.push('Keylogger pattern detected on password fields');
    }

    if (signals.hasFakeSecurityBadge && signals.brandMentionedNotOwner.length > 0) {
      score += 15;
      indicators.push('Fake SSL/security badge with brand impersonation');
    }

    if (signals.suspiciousTitle) {
      score += 10;
      indicators.push(`Suspicious page title impersonates: ${signals.brandMentionedNotOwner.join(', ')}`);
    }

    const finalScore = Math.min(100, score);
    const verdict: SandboxVerdict =
      finalScore >= 60 ? 'malicious' :
      finalScore >= 30 ? 'suspicious' :
      'clean';

    return {
      url,
      verdict,
      score: finalScore,
      signals: { ...signals, analysisDurationMs: Date.now() - startTime },
      threatIndicators: indicators,
      analyzedAt: Date.now(),
    };
  }

  // ─── Helpers ────────────────────────────────────────────────────────────────

  private async timeoutResult(url: string, ms: number): Promise<SandboxAnalysisResult> {
    await new Promise(r => setTimeout(r, ms));
    return {
      url,
      verdict: 'timeout',
      score: 0,
      signals: {
        redirectCount: 0, finalUrl: url, crossOriginRedirect: false,
        hasLoginForm: false, hasPasswordField: false, hasFakeSecurityBadge: false,
        downloadsFile: false, hasObfuscatedJs: false, hasKeylogger: false,
        hasClipboardAccess: false, brandMentionedNotOwner: [],
        suspiciousTitle: false, analysisDurationMs: ms, timedOut: true,
      },
      threatIndicators: [`Analysis timed out after ${ms}ms`],
      analyzedAt: Date.now(),
    };
  }

  private errorResult(url: string, reason: string): SandboxAnalysisResult {
    return {
      url, verdict: 'error', score: 0,
      signals: {
        redirectCount: 0, finalUrl: url, crossOriginRedirect: false,
        hasLoginForm: false, hasPasswordField: false, hasFakeSecurityBadge: false,
        downloadsFile: false, hasObfuscatedJs: false, hasKeylogger: false,
        hasClipboardAccess: false, brandMentionedNotOwner: [],
        suspiciousTitle: false, analysisDurationMs: 0, timedOut: false,
      },
      threatIndicators: [reason],
      analyzedAt: Date.now(),
    };
  }

  private chunkArray<T>(arr: T[], size: number): T[][] {
    const chunks: T[][] = [];
    for (let i = 0; i < arr.length; i += size) chunks.push(arr.slice(i, i + size));
    return chunks;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// HOW TO INTEGRATE IN url-analysis.service.ts
// ─────────────────────────────────────────────────────────────────────────────
//
// في url-analysis.service.ts أضف:
//
//   constructor(
//     private readonly intel: IntelligenceCacheService,
//     @Optional() private readonly grpcClient: ClientGrpc | null,
//     @Optional() private readonly sandbox: UrlSandboxService | null,  // ← أضف
//   ) {}
//
//   async analyzeUrl(url: string): Promise<UrlAnalysisResult> {
//     // Stage 1: Static analysis (fast)
//     const staticResult = await this.intel.lookupUrl(url);
//
//     // Stage 2: Dynamic sandbox (triggered on suspicious static results)
//     if (this.sandbox && staticResult.score >= 40) {
//       const dynamicResult = await this.sandbox.analyze(url);
//       if (dynamicResult.verdict === 'malicious') {
//         return { ...staticResult, verdict: 'malicious', score: Math.max(staticResult.score, dynamicResult.score) };
//       }
//     }
//
//     return staticResult;
//   }
//
// ─────────────────────────────────────────────────────────────────────────────
// INSTALLATION
// ─────────────────────────────────────────────────────────────────────────────
//
//   npm install playwright
//   npx playwright install chromium
//
// في Docker:
//   RUN npx playwright install --with-deps chromium
//
// ─────────────────────────────────────────────────────────────────────────────
// STAGE 3: CAPEv2 Detonation (للـ high-risk URLs)
// ─────────────────────────────────────────────────────────────────────────────
//
//   if (dynamicResult.verdict === 'malicious' && dynamicResult.score >= 80) {
//     // Submit to CAPEv2 (same server بيستخدمه الـ malware scanner)
//     const capeResult = await this.capeClient.submitUrl({ url });
//     // CAPEv2 بيعمل full browser detonation مع exploit detection
//     // Returns: malware_family، behavior_report، network_iocs
//   }
//
// ─────────────────────────────────────────────────────────────────────────────
