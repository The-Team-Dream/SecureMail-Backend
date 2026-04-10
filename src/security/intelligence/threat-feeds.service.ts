import { Injectable, Logger, Optional } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import {
  checkIpAbuseIPDB,
  checkIpVirusTotal,
  checkIpSpamhaus,
  checkIpInfo,
  checkGreyNoise,
  checkDomainVirusTotal,
  checkDomainAbuseIPDB,
  checkDomainWhois,
  checkUrlPhishTank,
  checkUrlScan,
  checkUrlVirusTotal,
} from './feeds';
import { FeedDomainResult, FeedIpResult, FeedUrlResult, ThreatFeedsConfig } from 'src/security/types';

@Injectable()
export class ThreatFeedsService {
  private readonly logger = new Logger(ThreatFeedsService.name);
  private readonly config: ThreatFeedsConfig;

  constructor(@Optional() configService?: ConfigService) {
    this.config = {
      abuseIpDbKey: configService?.get<string>('ABUSEIPDB_API_KEY') ?? '',
      virusTotalKey: configService?.get<string>('VIRUSTOTAL_API_KEY') ?? '',
      urlScanKey: configService?.get<string>('URLSCAN_API_KEY') ?? '',
      phishTankKey: configService?.get<string>('PHISHTANK_API_KEY') ?? '',
      ipinfoKey: configService?.get<string>('IPINFO_API_KEY') ?? '',
      greynoiseKey: configService?.get<string>('GREYNOISE_API_KEY') ?? '',
    };

    if (!this.config.abuseIpDbKey) {
      this.logger.warn('ABUSEIPDB_API_KEY not set — IP reputation disabled.');
    }
    if (!this.config.virusTotalKey) {
      this.logger.warn('VIRUSTOTAL_API_KEY not set — VirusTotal disabled.');
    }
    if (!this.config.urlScanKey) {
      this.logger.warn('URLSCAN_API_KEY not set — URLScan disabled.');
    }
    if (!this.config.phishTankKey) {
      this.logger.warn('PHISHTANK_API_KEY not set — PhishTank disabled.');
    }
  }

  // ──────────────── Lookup IP ─────────────────────────
  async lookupIp(ip: string): Promise<FeedIpResult> {
    try {
      const [abuse, vt, spamhaus, ipinfo, greynoise] = await Promise.all([
        checkIpAbuseIPDB(ip, this.config.abuseIpDbKey).catch(() => null),
        checkIpVirusTotal(ip, this.config.virusTotalKey).catch(() => null),
        checkIpSpamhaus(ip).catch(() => false),
        checkIpInfo(ip, this.config.ipinfoKey).catch(() => null),
        checkGreyNoise(ip, this.config.greynoiseKey).catch(() => null),
      ]);

      return {
        ip,
        ipReputationScore: abuse?.ipReputationScore ?? vt?.ipReputationScore ?? 0,
        isIpBlacklisted: abuse?.isIpBlacklisted ?? vt?.isIpBlacklisted ?? spamhaus ?? false,
        ipCountry: ipinfo?.ipCountry ?? abuse?.ipCountry ?? vt?.ipCountry,
        asn: vt?.asn ?? ipinfo?.asn,
        asOwner: vt?.asOwner ?? ipinfo?.asOwner,
        network: vt?.network ?? ipinfo?.network,
        isIpDatacenter: abuse?.isIpDatacenter ?? ipinfo?.isIpDatacenter ?? false,
        isIpTor: abuse?.isIpTor ?? false,
        isIpProxy: abuse?.isIpProxy ?? false,
        maliciousEngines: vt?.maliciousEngines,
        suspiciousEngines: vt?.suspiciousEngines,
        analysisEngines: vt?.analysisEngines,
        ipReports: abuse?.ipReports,
        distinctUsers: abuse?.distinctUsers,
        lastReportedAt: abuse?.lastReportedAt,
        vtReputation: vt?.vtReputation,
        hostingProvider: ipinfo?.hostingProvider ?? vt?.asOwner,
        ipType: ipinfo?.ipType,
        isScanner: greynoise?.isScanner,
        isKnownAttacker: greynoise?.isKnownAttacker,
      };
    } catch (err) {
      this.logger.error(`lookupIp failed for ${ip}: ${err}`);
      return this.localIpFallback(ip);
    }
  }

  // ──────────────── Lookup Domain ─────────────────────
  async lookupDomain(domain: string): Promise<FeedDomainResult> {
    try {
      const [vt, abuse, whois] = await Promise.all([
        checkDomainVirusTotal(domain, this.config.virusTotalKey).catch(() => null),
        checkDomainAbuseIPDB(domain, this.config.abuseIpDbKey).catch(() => null),
        checkDomainWhois(domain).catch(() => null),
      ]);
      return {
        domain,
        domainReputationScore: vt?.domainReputationScore ?? abuse?.domainReputationScore ?? 0,
        domainBlacklisted: vt?.domainBlacklisted ?? abuse?.domainBlacklisted ?? false,
        domainAgeDays: whois?.domainAgeDays ?? 0,
        newlyRegisteredDomain: whois?.newlyRegisteredDomain ?? false,
        domainRegistrar: whois?.domainRegistrar ?? 'unknown',
        whoisHidden: whois?.whoisHidden ?? false,
      };
    } catch (err) {
      this.logger.error(`lookupDomain failed for ${domain}: ${err}`);
      return this.unknownDomainFallback(domain);
    }
  }

  // ──────────────── Lookup URL ─────────────────────
  async lookupUrl(url: string): Promise<FeedUrlResult> {
    try {
      const [vt, phishtank, urlscan] = await Promise.all([
        checkUrlVirusTotal(url, this.config.virusTotalKey).catch(() => null),
        checkUrlPhishTank(url, this.config.phishTankKey).catch(() => null),
        checkUrlScan(url, this.config.urlScanKey).catch(() => null),
      ]);
      const sources: string[] = []
      let threatScore = 0
      let threat: string | undefined
      if (vt?.isBlacklisted) {
        sources.push('VirusTotal')
        threatScore = Math.max(threatScore, vt.score)
        threat = vt.threat ?? threat
      }
      if (phishtank?.isBlacklisted) {
        sources.push('PhishTank')
        threatScore = Math.max(threatScore, phishtank.score)
        threat = phishtank.threat ?? threat
      }
      if (urlscan?.isBlacklisted) {
        sources.push('URLScan')
        threatScore = Math.max(threatScore, urlscan.score)
        threat = urlscan.threat ?? threat
      }
      return {
        url,
        isBlacklisted: sources.length > 0,
        threatScore,
        sources,
        threat
      }
    } catch (err) {
      this.logger.warn(`lookupUrl failed for ${url}: ${err}`)
      return {
        url,
        isBlacklisted: false,
        threatScore: 0,
        sources: []
      }
    }
  }


  // ──────────────── Private Helpers ───────────────────
  private localIpFallback(ip: string): FeedIpResult {
    return { ip, ipReputationScore: 0 };
  }

  private unknownDomainFallback(domain: string): FeedDomainResult {
    return { domain, domainReputationScore: 0, };
  }
}
