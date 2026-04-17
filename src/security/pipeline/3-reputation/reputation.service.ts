import { Injectable, Logger, Optional, Inject, OnModuleInit } from '@nestjs/common';
import { Observable, firstValueFrom } from 'rxjs';
import { UNKNOWN_REPUTATION } from 'src/security/constants';
import { IntelligenceCacheService } from '../../intelligence/intelligence-cache.service';
import { ParsedEmail, ReputationSignals } from 'src/security/types';

@Injectable()
export class ReputationService {
  private readonly logger = new Logger(ReputationService.name);
  constructor(
    private readonly intel: IntelligenceCacheService,
  ) { }


  async check(email: ParsedEmail): Promise<ReputationSignals> {
    try {
      return await this.doCheck(email);
    } catch (err) {
      this.logger.warn(
        `ReputationService.check failed (non-fatal): ${err instanceof Error ? err.message : String(err)
        }`
      );
      return UNKNOWN_REPUTATION;
    }
  }

  private async doCheck(email: ParsedEmail): Promise<ReputationSignals> {
    const senderIp = email.senderIp ?? '';
    const senderDomain = email.fromFullDomain ?? '';

    const [ipLookupResult, domainLookupResult] = await Promise.all([
      senderIp ? this.intel.lookupIp(senderIp) : Promise.resolve(null),
      senderDomain ? this.intel.lookupDomain(senderDomain) : Promise.resolve(null),
    ]);

    return {
      // ── IP reputation ─────────────────────────────────────────
      ipReputationScore: ipLookupResult?.ipReputationScore ?? 0,
      isIpBlacklisted: ipLookupResult?.isIpBlacklisted ?? false,
      ipCountry: ipLookupResult?.ipCountry ?? 'unknown',
      isIpDatacenter: ipLookupResult?.isIpDatacenter ?? false,
      isIpTor: ipLookupResult?.isIpTor ?? false,
      isIpProxy: ipLookupResult?.isIpProxy ?? false,

      // ── Domain reputation ─────────────────────────────────────
      domainReputationScore: domainLookupResult?.domainReputationScore ?? 0,
      domainBlacklisted: domainLookupResult?.domainBlacklisted ?? false,
      domainAgeDays: domainLookupResult?.domainAgeDays,
      newlyRegisteredDomain: domainLookupResult?.newlyRegisteredDomain ?? false,
      domainRegistrar: domainLookupResult?.domainRegistrar ?? 'unknown',
      mxRecordsExist: domainLookupResult?.mxRecordsExist ?? false,
      whoisHidden: domainLookupResult?.whoisHidden ?? false,
    };
  }

}
