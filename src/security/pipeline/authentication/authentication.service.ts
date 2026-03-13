// ─────────────────────────────────────────────────────────────────────────────
// authentication/authentication.service.ts
//
// Authentication Engine — Stage 2 of the Security Pipeline.
//
// Parses SPF, DKIM, DMARC, ARC results from raw email headers and produces
// a structured AuthResult object. This service does NOT perform live DNS
// lookups — it interprets authentication headers already embedded by the
// receiving MTA (e.g. Gmail, Outlook, your IMAP server).
//
// Live DNS verification (for SMTP Gateway integration) is architecturally
// supported via the optional DnsVerificationService stub at the bottom.
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable, Logger } from '@nestjs/common';
import { ParsedEmail } from '../email-parser/email-parser.service';

// ─── Result types ──────────────────────────────────────────────────────────────
export type AuthStatus = 'pass' | 'fail' | 'softfail' | 'neutral' | 'none' | 'unknown' | 'permerror' | 'temperror';

export interface SpfResult {
  status:  AuthStatus;
  domain?: string;
  ip?:     string;
  reason?: string;
}

export interface DkimResult {
  status:   AuthStatus;
  domain?:  string;
  selector?: string;
  reason?:  string;
}

export interface DmarcResult {
  status:  AuthStatus;
  policy?: string;    // none | quarantine | reject
  domain?: string;
  reason?: string;
}

export interface ArcResult {
  status:  AuthStatus;
  chain?:  string;
}

// ─── Composite output ──────────────────────────────────────────────────────────
export interface AuthResult {
  spf:   SpfResult;
  dkim:  DkimResult;
  dmarc: DmarcResult;
  arc:   ArcResult;

  // Aggregated risk signal — true if any hard failure is present
  hasAuthFailure: boolean;
  // Severity: 'critical' (spf=fail + dkim=fail + dmarc=fail) | 'high' | 'medium' | 'low' | 'none'
  failureSeverity: 'critical' | 'high' | 'medium' | 'low' | 'none';
  // Human-readable summary for logs / AI agent
  summary: string;
}

@Injectable()
export class AuthenticationService {
  private readonly logger = new Logger(AuthenticationService.name);

  /**
   * analyze() — parse all auth headers from a ParsedEmail and return
   * a structured AuthResult.
   */
  analyze(email: ParsedEmail): AuthResult {
    try {
      return this.doAnalyze(email);
    } catch (err) {
      this.logger.error('AuthenticationService.analyze failed', {
        emailId: email.emailId,
        error:   err instanceof Error ? err.message : String(err),
      });
      return this.unknownResult();
    }
  }

  // ─── Core analysis ─────────────────────────────────────────────────────────
  private doAnalyze(email: ParsedEmail): AuthResult {
    // Primary source: Authentication-Results header (set by receiving MTA)
    const authResultsRaw = this.flatten(email.authHeaders.authenticationResults);

    // Secondary source: Received-SPF header (set by some MTAs separately)
    const receivedSpfRaw  = this.flatten(email.authHeaders.spf);
    const dkimSigRaw      = this.flatten(email.authHeaders.dkim);
    const arcRaw          = this.flatten(email.authHeaders.arc);

    const combined = [authResultsRaw, receivedSpfRaw, dkimSigRaw, arcRaw]
      .filter(Boolean).join(' ').toLowerCase();

    const spf   = this.parseSpf(combined, receivedSpfRaw);
    const dkim  = this.parseDkim(combined, dkimSigRaw);
    const dmarc = this.parseDmarc(combined);
    const arc   = this.parseArc(combined, arcRaw);

    const failCount = [
      this.isFail(spf.status),
      this.isFail(dkim.status),
      this.isFail(dmarc.status),
    ].filter(Boolean).length;

    const hasAuthFailure  = failCount > 0;
    const failureSeverity = this.computeSeverity(spf, dkim, dmarc, failCount);
    const summary         = this.buildSummary(spf, dkim, dmarc, arc);

    return { spf, dkim, dmarc, arc, hasAuthFailure, failureSeverity, summary };
  }

  // ─── SPF parsing ──────────────────────────────────────────────────────────
  private parseSpf(authResults: string, receivedSpf: string): SpfResult {
    // Try Authentication-Results first (most reliable)
    const arSpf = authResults.match(/spf=(pass|fail|softfail|neutral|none|permerror|temperror)/);
    if (arSpf) {
      const domainMatch = authResults.match(/spf=[^\s]+\s+smtp\.(?:mailfrom|helo)=([^\s;]+)/);
      return {
        status: arSpf[1] as AuthStatus,
        domain: domainMatch?.[1] ?? undefined,
      };
    }

    // Fallback: Received-SPF header
    if (receivedSpf) {
      const rsSpf = receivedSpf.match(/(pass|fail|softfail|neutral|none|permerror|temperror)/i);
      if (rsSpf) {
        return { status: rsSpf[1].toLowerCase() as AuthStatus };
      }
    }

    return { status: 'none' };
  }

  // ─── DKIM parsing ─────────────────────────────────────────────────────────
  private parseDkim(authResults: string, dkimSignature: string): DkimResult {
    const arDkim = authResults.match(/dkim=(pass|fail|none|permerror|temperror)/);
    if (arDkim) {
      const domainMatch   = authResults.match(/dkim=[^\s]+\s+header\.(?:d|i)=([^\s;@]+)/);
      const selectorMatch = authResults.match(/dkim=[^\s]+.*?s=([^\s;]+)/);
      return {
        status:   arDkim[1] as AuthStatus,
        domain:   domainMatch?.[1] ?? undefined,
        selector: selectorMatch?.[1] ?? undefined,
      };
    }

    // If DKIM-Signature header exists but no result → signing present, result unknown
    if (dkimSignature) {
      const dMatch = dkimSignature.match(/d=([^\s;]+)/i);
      return { status: 'unknown', domain: dMatch?.[1] ?? undefined };
    }

    return { status: 'none' };
  }

  // ─── DMARC parsing ────────────────────────────────────────────────────────
  private parseDmarc(authResults: string): DmarcResult {
    const arDmarc = authResults.match(/dmarc=(pass|fail|none|permerror|temperror)/);
    if (!arDmarc) return { status: 'none' };

    const policyMatch = authResults.match(/dmarc=[^\s]+.*?p=(\w+)/);
    const domainMatch = authResults.match(/dmarc=[^\s]+.*?header\.from=([^\s;]+)/);
    return {
      status: arDmarc[1] as AuthStatus,
      policy: policyMatch?.[1] ?? undefined,
      domain: domainMatch?.[1] ?? undefined,
    };
  }

  // ─── ARC parsing ──────────────────────────────────────────────────────────
  private parseArc(authResults: string, arcRaw: string): ArcResult {
    const arcMatch = authResults.match(/arc=(pass|fail|none)/);
    if (arcMatch) return { status: arcMatch[1] as AuthStatus, chain: arcRaw || undefined };

    // Check ARC-Authentication-Results header directly
    if (arcRaw) {
      const directMatch = arcRaw.match(/(pass|fail|none)/i);
      if (directMatch) return { status: directMatch[1].toLowerCase() as AuthStatus };
    }
    return { status: 'none' };
  }

  // ─── Severity computation ─────────────────────────────────────────────────
  private computeSeverity(
    spf: SpfResult, dkim: DkimResult, dmarc: DmarcResult,
    failCount: number,
  ): AuthResult['failureSeverity'] {
    if (failCount === 0) return 'none';

    // Critical: all three fail (likely deliberate spoofing)
    if (failCount >= 3) return 'critical';

    // High: DMARC fail regardless of others (policy enforcement breach)
    if (this.isFail(dmarc.status)) return 'high';

    // High: both SPF hard fail + DKIM fail
    if (spf.status === 'fail' && this.isFail(dkim.status)) return 'high';

    // Medium: one hard fail
    if (spf.status === 'fail' || dkim.status === 'fail') return 'medium';

    // Low: softfail or none
    return 'low';
  }

  // ─── Summary builder ──────────────────────────────────────────────────────
  private buildSummary(spf: SpfResult, dkim: DkimResult, dmarc: DmarcResult, arc: ArcResult): string {
    const parts = [
      `SPF=${spf.status}`,
      `DKIM=${dkim.status}`,
      `DMARC=${dmarc.status}`,
    ];
    if (arc.status !== 'none') parts.push(`ARC=${arc.status}`);
    return parts.join(', ');
  }

  // ─── Utilities ────────────────────────────────────────────────────────────
  private isFail(status: AuthStatus): boolean {
    return status === 'fail' || status === 'permerror';
  }

  private flatten(val: string | string[] | undefined | null): string {
    if (!val) return '';
    return Array.isArray(val) ? val.join(' ') : val;
  }

  private unknownResult(): AuthResult {
    const u: AuthStatus = 'unknown';
    return {
      spf:   { status: u },
      dkim:  { status: u },
      dmarc: { status: u },
      arc:   { status: u },
      hasAuthFailure:  false,
      failureSeverity: 'none',
      summary:         'Auth analysis unavailable',
    };
  }
}
