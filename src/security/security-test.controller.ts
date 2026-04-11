// ─────────────────────────────────────────────────────────────────────────────
// security/security-test.controller.ts
//
// SecurityTestController — Manual testing endpoints for the Security Pipeline.
//
// ⚠️  FOR DEVELOPMENT / TESTING ONLY — disable in production by removing
//     SecurityTestModule from app.module.ts or guarding with an env flag.
//
// Endpoints:
//   POST /security-test/analyze          — Run full pipeline on arbitrary input
//   POST /security-test/analyze/phishing — Pre-built phishing scenario
//   POST /security-test/analyze/bec      — Pre-built BEC scenario
//   POST /security-test/analyze/malware  — Pre-built malware scenario
//   POST /security-test/analyze/spam     — Pre-built spam scenario
//   POST /security-test/analyze/clean    — Pre-built clean email scenario
//   GET  /security-test/cache/stats      — Cache statistics
//   POST /security-test/cache/invalidate — Invalidate a cache entry
//   POST /security-test/intel/hash       — Test single file hash lookup
//   POST /security-test/intel/url        — Test single URL lookup
//   POST /security-test/intel/ip         — Test single IP lookup
//   POST /security-test/intel/domain     — Test single domain lookup
//
// Usage (curl examples):
//
//   # Run full pipeline on custom email:
//   curl -X POST http://localhost:3000/security-test/analyze \
//     -H "Content-Type: application/json" \
//     -d '{"fromAddr":"phish@evil.tk","subject":"Urgent: Verify your account","bodyText":"Click here NOW"}'
//
//   # Run built-in BEC scenario:
//   curl -X POST http://localhost:3000/security-test/analyze/bec
//
//   # Check cache stats:
//   curl http://localhost:3000/security-test/cache/stats
//
//   # Test a specific URL:
//   curl -X POST http://localhost:3000/security-test/intel/url \
//     -H "Content-Type: application/json" \
//     -d '{"url":"https://bit.ly/phishing123"}'
// ─────────────────────────────────────────────────────────────────────────────

import {
  Controller, Get, Post, Body,
  HttpCode, HttpStatus, Logger,
} from '@nestjs/common';
import { ApiBody, ApiOperation, ApiTags } from '@nestjs/swagger';
import { SecurityService, SecurityPipelineInput } from './security.service';
import { IntelligenceCacheService } from './intelligence/intelligence-cache.service';
import { Throttle } from '@nestjs/throttler';
import {
  AnalyzeEmailDto,
  CacheInvalidateDto,
  IntelDomainDto,
  IntelIpDto,
  IntelUrlDto,
} from './dto/security-test.dto';
import { ApiOkWrapped, ApiPublicErrorResponses } from 'src/common/swagger';

// ─── Scenario definitions ──────────────────────────────────────────────────────

const SCENARIOS: Record<string, SecurityPipelineInput & { _userId: number }> = {

  phishing: {
    _userId: 1,
    emailId: 'test-phishing-001',
    messageId: '<phishing@evil.tk>',
    mailBoxId: 1,
    fromAddr: '"PayPal Security" <security-noreply@paypa1.tk>',
    fromName: 'PayPal Security',
    subject: '⚠️ Urgent: Your PayPal account has been suspended',
    bodyHtml: `
      <p>Dear Customer,</p>
      <p>We have detected suspicious activity on your account.</p>
      <p>You must verify your account immediately to avoid suspension.</p>
      <p><a href="https://paypal-verify.tk/login?token=abc123">Click here to verify NOW</a></p>
      <p>Failure to verify within 24 hours will result in permanent account termination.</p>
      <form action="https://evil.tk/harvest">
        <input type="password" name="password" placeholder="Enter Password" />
      </form>
    `,
    headers: {
      'authentication-results': 'mx.google.com; spf=fail smtp.mailfrom=paypa1.tk; dkim=fail; dmarc=fail',
    },
  },

  bec: {
    _userId: 1,
    emailId: 'test-bec-001',
    messageId: '<bec@attacker.com>',
    mailBoxId: 1,
    fromAddr: '"CEO John Smith" <johnsmith.ceo@gmail.com>',
    fromName: 'CEO John Smith',
    subject: 'Confidential: Wire Transfer Required ASAP',
    bodyText: `
      Hi,

      I need you to process an urgent wire transfer of $50,000 to our new vendor.
      This is time-sensitive and confidential — please do not discuss with anyone.

      Bank: First National Bank
      Account: 1234567890
      Routing: 987654321

      Process this immediately and confirm by reply.

      Best,
      John Smith
      CEO
    `,
    headers: {
      'reply-to': 'john.smith.payments@protonmail.com',
    },
  },

  malware: {
    _userId: 1,
    emailId: 'test-malware-001',
    messageId: '<malware@attacker.com>',
    mailBoxId: 1,
    fromAddr: 'invoices@supplier-company.com',
    fromName: 'Accounts Payable',
    subject: 'Invoice #INV-2024-0892 — Action Required',
    bodyText: 'Please find attached the invoice for services rendered. Open the attachment to review.',
    attachments: [{
      filename: 'Invoice_2024.exe',
      mimeType: 'application/octet-stream',
      size: 245760,
      storagePath: '/tmp/test-invoice.exe',
    }],
  },

  spam: {
    _userId: 1,
    emailId: 'test-spam-001',
    messageId: '<spam@marketing.com>',
    mailBoxId: 1,
    fromAddr: 'noreply@newsletter.wellknownbrand.com',
    fromName: 'Amazing Deals',
    subject: '🎉 LIMITED TIME OFFER: 90% OFF everything! BUY NOW!!!',
    bodyText: `
      CONGRATULATIONS! You have been selected for our EXCLUSIVE offer!

      Buy now and SAVE 90% on all products!
      Free shipping on orders over $1!
      Act fast — this offer expires in 24 HOURS!

      Click here to claim your discount: https://wellknownbrand.com/deals

      To unsubscribe, click here.
    `,
    headers: { 'authentication-results': 'spf=pass dkim=pass dmarc=pass' },
  },

  clean: {
    _userId: 1,
    emailId: 'test-clean-001',
    messageId: '<clean@company.com>',
    mailBoxId: 1,
    fromAddr: '"Alice Johnson" <alice@company.com>',
    fromName: 'Alice Johnson',
    subject: 'Q3 Planning Meeting — Thursday 2pm',
    bodyText: 'Hi team, just a reminder about our Q3 planning meeting this Thursday at 2pm in Conference Room A. Please bring your Q2 reports.',
    headers: {
      'authentication-results': 'mx.google.com; spf=pass smtp.mailfrom=company.com; dkim=pass header.d=company.com; dmarc=pass',
    },
  },
};

// ─────────────────────────────────────────────────────────────────────────────

@ApiTags('security-test')
@ApiPublicErrorResponses()
@Controller('security-test')
@Throttle({ default: { limit: 5, ttl: 60000 } })
export class SecurityTestController {
  private readonly logger = new Logger(SecurityTestController.name);

  constructor(
    private readonly securityService: SecurityService,
    private readonly intel: IntelligenceCacheService,
  ) { }

  // ──────────────────────────────────────────────────────────────────────────
  // PIPELINE TESTING
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * POST /security-test/analyze
   * Run the full security pipeline on custom email data.
   */
  @Post('analyze')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({
    summary: 'Run security pipeline on custom payload',
    description: 'Dev/test only. Disabled in production deployments that omit SecurityTestModule.',
  })
  @ApiBody({ type: AnalyzeEmailDto })
  @ApiOkWrapped('Pipeline result summary', {
    scenario: 'custom',
    processingMs: 120,
    verdict: { label: 'SUSPICIOUS', riskScore: 0.72 },
  })
  async analyze(@Body() dto: AnalyzeEmailDto) {
    const input: SecurityPipelineInput = {
      emailId: `test-${Date.now()}`,
      messageId: `<test-${Date.now()}@securemail-test.local>`,
      mailBoxId: dto.mailBoxId ?? 1,
      fromAddr: dto.fromAddr ?? 'test@example.com',
      fromName: dto.fromName ?? null,
      toAddr: dto.toAddr ? [dto.toAddr] : ['user@company.com'],
      subject: dto.subject ?? '(No subject)',
      bodyText: dto.bodyText ?? null,
      bodyHtml: dto.bodyHtml ?? null,
      headers: dto.headers ?? null,
    };

    const userId = dto.userId ?? 1;
    const result = await this.securityService.analyze(input, userId);

    return this.formatResult(result, input);
  }

  /**
   * POST /security-test/analyze/:scenario
   * Run a pre-built test scenario.
   */
  @Post('analyze/phishing')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Run built-in phishing scenario' })
  @ApiOkWrapped('Pipeline result', { scenario: 'phishing', processingMs: 100 })
  async analyzePhishing() {
    return this.runScenario('phishing');
  }

  @Post('analyze/bec')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Run built-in BEC scenario' })
  @ApiOkWrapped('Pipeline result', { scenario: 'bec', processingMs: 100 })
  async analyzeBec() {
    return this.runScenario('bec');
  }

  @Post('analyze/malware')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Run built-in malware scenario' })
  @ApiOkWrapped('Pipeline result', { scenario: 'malware', processingMs: 100 })
  async analyzeMalware() {
    return this.runScenario('malware');
  }

  @Post('analyze/spam')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Run built-in spam scenario' })
  @ApiOkWrapped('Pipeline result', { scenario: 'spam', processingMs: 100 })
  async analyzeSpam() {
    return this.runScenario('spam');
  }

  @Post('analyze/clean')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Run built-in clean email scenario' })
  @ApiOkWrapped('Pipeline result', { scenario: 'clean', processingMs: 100 })
  async analyzeClean() {
    return this.runScenario('clean');
  }

  // ──────────────────────────────────────────────────────────────────────────
  // CACHE MANAGEMENT
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * GET /security-test/cache/stats
   * Returns Redis cache statistics.
   */
  @Get('cache/stats')
  @ApiOperation({ summary: 'Intelligence cache statistics' })
  @ApiOkWrapped('Cache stats', { timestamp: '2026-04-11T00:00:00.000Z', intel: {} })
  async getCacheStats() {
    const [intelStats] = await Promise.all([
      this.intel.getCacheStats(),
    ]);
    return {
      timestamp: new Date().toISOString(),
      intel: intelStats,
    };
  }

  /**
   * POST /security-test/cache/invalidate
   * Remove an entry from the cache.
   */
  @Post('cache/invalidate')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Invalidate intel cache entry' })
  @ApiBody({ type: CacheInvalidateDto })
  @ApiOkWrapped('Invalidation result', { success: true, invalidated: 'url:https://x' })
  async invalidateCache(@Body() dto: CacheInvalidateDto) {
    await this.intel.invalidate(dto.type, dto.value);
    return { success: true, invalidated: `${dto.type}:${dto.value}` };
  }


  /**
   * POST /security-test/intel/url
   * Test URL threat analysis.
   */
  @Post('intel/url')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Lookup URL reputation (test)' })
  @ApiBody({ type: IntelUrlDto })
  @ApiOkWrapped('URL intel', { malicious: false, lookupMs: 12 })
  async lookupUrl(@Body() dto: IntelUrlDto) {
    const start = Date.now();
    const result = await this.intel.lookupUrl(dto.url);
    return { ...result, lookupMs: Date.now() - start };
  }

  /**
   * POST /security-test/intel/ip
   * Test IP reputation lookup.
   */
  @Post('intel/ip')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Lookup IP reputation (test)' })
  @ApiBody({ type: IntelIpDto })
  @ApiOkWrapped('IP intel', { lookupMs: 8 })
  async lookupIp(@Body() dto: IntelIpDto) {
    const start = Date.now();
    const result = await this.intel.lookupIp(dto.ip);
    return { ...result, lookupMs: Date.now() - start };
  }

  /**
   * POST /security-test/intel/domain
   * Test domain reputation lookup.
   */
  @Post('intel/domain')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Lookup domain reputation (test)' })
  @ApiBody({ type: IntelDomainDto })
  @ApiOkWrapped('Domain intel', { lookupMs: 10 })
  async lookupDomain(@Body() dto: IntelDomainDto) {
    const start = Date.now();
    const result = await this.intel.lookupDomain(dto.domain);
    return { ...result, lookupMs: Date.now() - start };
  }

  // ──────────────────────────────────────────────────────────────────────────
  // PRIVATE HELPERS
  // ──────────────────────────────────────────────────────────────────────────

  private async runScenario(name: string) {
    const scenario = SCENARIOS[name];
    if (!scenario) {
      return { error: `Unknown scenario: ${name}` };
    }
    const { _userId, ...input } = scenario;
    const result = await this.securityService.analyze(input as SecurityPipelineInput, _userId);
    return this.formatResult(result, input as SecurityPipelineInput, name);
  }

  private formatResult(result: any, input: SecurityPipelineInput, scenario?: string) {
    return {
      scenario: scenario ?? 'custom',
      timestamp: new Date().toISOString(),
      // ── Performance ───────────────────────────────────────────────────────
      processingMs: result.processingMs,

      // ── Summary ──────────────────────────────────────────────────────────
      verdict: {
        label: result.verdict.label,
        riskScore: result.verdict.riskScore,
        confidence: result.verdict.confidence,
        action: result.verdict.action,
        explanation: result.verdict.explanation,
        attackPatterns: result.verdict.attackPatterns,
        recommendations: result.verdict.recommendations,
      },

      riskAssessment: result.riskAssessment,

      // ── Authentication ────────────────────────────────────────────────────
      authentication: result.authSummary,

      // ── Triggered rules ───────────────────────────────────────────────────
      triggeredRules: result.ruleHits.map((r: any) => ({
        rule: r.rule,
        score: r.score,
        description: r.description,
      })),

      // ── Email parsed signals ──────────────────────────────────────────────
      parsedEmail: {
        fromDomain: result.parsedEmail.fromDomain,
        fromFullDomain: result.parsedEmail.fromFullDomain,
        urlCount: result.parsedEmail.urls.length,
        urls: result.parsedEmail.urls.slice(0, 5),
        hasAttachment: result.parsedEmail.hasAttachment,
        isReplyThread: result.parsedEmail.isReplyThread,
      },
      // ── AI report (if available) ──────────────────────────────────────────
      aiReport: result.aiReport ? {
        verdict: result.aiReport.verdict,
        summary: result.aiReport.summary,
        isCampaign: result.aiReport.isCampaign,
        isAnomaly: result.aiReport.behavioral_anomaly,
      } : null,

      // ── Input echo (for debugging) ────────────────────────────────────────
      input: {
        from: input.fromAddr,
        subject: input.subject,
        mailBoxId: input.mailBoxId,
      },
    };
  }
}
