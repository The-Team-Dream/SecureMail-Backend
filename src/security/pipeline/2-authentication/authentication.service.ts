import { Injectable, Logger } from '@nestjs/common';
import { ArcResult, AuthSignals, AuthStatus, DkimResult, DmarcResult, ParsedEmail, SpfResult } from 'src/security/types';

@Injectable()
export class AuthenticationService {
  private readonly logger = new Logger(AuthenticationService.name);

  analyze(email: ParsedEmail): AuthSignals {
    try {
      return this.doAnalyze(email);
    } catch (err) {
      this.logger.error('AuthenticationService.analyze failed', {
        emailId: email.emailId,
        error: err instanceof Error ? err.message : String(err),
      });
      return this.unknownResult();
    }
  }

  private doAnalyze(email: ParsedEmail): AuthSignals {
    const authResultsRaw = this.flatten(email.authHeaders.authenticationResults);
    const receivedSpfRaw = this.flatten(email.authHeaders.spf);
    const dkimSigRaw = this.flatten(email.authHeaders.dkim);
    const arcRaw = this.flatten(email.authHeaders.arc);
    const combined = [authResultsRaw, receivedSpfRaw, dkimSigRaw, arcRaw].filter(Boolean).join(' ').toLowerCase();
    const spf = this.parseSpf(combined, receivedSpfRaw);
    const dkim = this.parseDkim(combined, dkimSigRaw);
    const dmarc = this.parseDmarc(combined);
    const arc = this.parseArc(combined, arcRaw);
    const failCount = [
      this.isFail(spf.status),
      this.isFail(dkim.status),
      this.isFail(dmarc.status),
    ].filter(Boolean).length;
    const hasAuthFailure = failCount > 0;
    const failureSeverity = this.computeSeverity(spf, dkim, dmarc, failCount);
    const summary = this.buildSummary(spf, dkim, dmarc, arc);
    return { spf, dkim, dmarc, arc, hasAuthFailure, failureSeverity, summary };
  }

  private parseSpf(authResults: string, receivedSpf: string): SpfResult {
    const arSpf = authResults.match(/spf=(pass|fail|softfail|neutral|none|permerror|temperror)/);
    if (arSpf) {
      const domainMatch = authResults.match(/spf=[^\s]+\s+smtp\.(?:mailfrom|helo)=([^\s;]+)/);
      return {
        status: arSpf[1] as AuthStatus,
        domain: domainMatch?.[1] ?? undefined,
      };
    }
    if (receivedSpf) {
      const rsSpf = receivedSpf.match(/(pass|fail|softfail|neutral|none|permerror|temperror)/i);
      if (rsSpf) {
        return { status: rsSpf[1].toLowerCase() as AuthStatus };
      }
    }
    return { status: 'none' };
  }

  private parseDkim(authResults: string, dkimSignature: string): DkimResult {
    const arDkim = authResults.match(/dkim=(pass|fail|none|permerror|temperror)/);
    if (arDkim) {
      const domainMatch = authResults.match(/dkim=[^\s]+\s+header\.(?:d|i)=([^\s;@]+)/);
      const selectorMatch = authResults.match(/dkim=[^\s]+.*?s=([^\s;]+)/);
      return {
        status: arDkim[1] as AuthStatus,
        domain: domainMatch?.[1] ?? undefined,
        selector: selectorMatch?.[1] ?? undefined,
      };
    }
    if (dkimSignature) {
      const dMatch = dkimSignature.match(/d=([^\s;]+)/i);
      return { status: 'unknown', domain: dMatch?.[1] ?? undefined };
    }
    return { status: 'none' };
  }

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

  private parseArc(authResults: string, arcRaw: string): ArcResult {
    const arcMatch = authResults.match(/arc=(pass|fail|none)/);
    if (arcMatch) return { status: arcMatch[1] as AuthStatus, chain: arcRaw || undefined };
    if (arcRaw) {
      const directMatch = arcRaw.match(/(pass|fail|none)/i);
      if (directMatch) return { status: directMatch[1].toLowerCase() as AuthStatus };
    }
    return { status: 'none' };
  }

  private computeSeverity(
    spf: SpfResult, dkim: DkimResult, dmarc: DmarcResult,
    failCount: number,
  ): AuthSignals['failureSeverity'] {
    if (failCount === 0) return 'none';
    if (failCount >= 3) return 'critical';
    if (this.isFail(dmarc.status)) return 'high';
    if (this.isFail(spf.status) && this.isFail(dkim.status)) return 'high';
    if (this.isFail(spf.status) || dkim.status === 'fail') return 'medium';
    return 'low';
  }

  private buildSummary(spf: SpfResult, dkim: DkimResult, dmarc: DmarcResult, arc: ArcResult): string {
    const parts = [
      `SPF=${spf.status}`,
      `DKIM=${dkim.status}`,
      `DMARC=${dmarc.status}`,
    ];
    if (arc.status !== 'none') parts.push(`ARC=${arc.status}`);
    return parts.join(', ');
  }

  private isFail(status: AuthStatus): boolean {
    return status === 'fail' || status === 'permerror';
  }

  private flatten(val: string | string[] | undefined | null): string {
    if (!val) return '';
    return Array.isArray(val) ? val.join(' ') : val;
  }

  private unknownResult(): AuthSignals {
    const u: AuthStatus = 'unknown';
    return {
      spf: { status: u },
      dkim: { status: u },
      dmarc: { status: u },
      arc: { status: u },
      hasAuthFailure: false,
      failureSeverity: 'none',
      summary: 'Auth analysis unavailable',
    };
  }
}
