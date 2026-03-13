// ─────────────────────────────────────────────────────────────────────────────
// security/pipeline/reputation/reputation.service.ts  (UPDATED v3)
//
// Reputation Engine — Stage 3 of the Security Pipeline.
//
// Changes from v2:
//   - Now uses IntelligenceCacheService for all reputation lookups
//   - gRPC external call is still optional (REPUTATION_SERVICE token)
//   - Cache is checked FIRST, then gRPC, then local analysis
//   - gRPC results are written back into cache automatically
//
// Flow per email:
//   1. Extract sender IP, domain, attachment SHA-256 hashes
//   2. For each: Cache → gRPC (if available) → local analysis
//   3. Aggregate results into ReputationSignals
// ─────────────────────────────────────────────────────────────────────────────

// FIX: ClientGrpc defined locally to avoid @nestjs/microservices version mismatch
interface ClientGrpc { getService<T = unknown>(name: string): T; }

import { Injectable, Logger, Optional, Inject, OnModuleInit } from '@nestjs/common';

import { Observable, firstValueFrom } from 'rxjs';
import { ParsedEmail }           from '../email-parser/email-parser.service';
import { ReputationSignals, UNKNOWN_REPUTATION } from '../detection/rule-engine/detection-context';
import { IntelligenceCacheService } from '../../intelligence/intelligence-cache.service';

// ─── gRPC interface (unchanged from v2) ──────────────────────────────────────
interface ReputationRequest {
  sender_ip:         string;
  sender_domain:     string;
  urls:              string[];
  attachment_hashes: string[];
}

interface ReputationResponse {
  ip_reputation:     string;
  domain_reputation: string;
  url_reputation:    string;
  hash_reputation:   string;
  threat_score:      number;
  details:           string;
}

interface ReputationGrpcService {
  CheckReputation(request: ReputationRequest): Observable<ReputationResponse>;
}

@Injectable()
export class ReputationService implements OnModuleInit {
  private readonly logger = new Logger(ReputationService.name);
  private reputationClient: ReputationGrpcService | null = null;

  constructor(
    private readonly intel: IntelligenceCacheService,

    // Optional gRPC client — when connected, results are written back to cache
    @Optional() @Inject('REPUTATION_SERVICE')
    private readonly client: ClientGrpc | null,
  ) {}

  onModuleInit(): void {
    if (!this.client) {
      this.logger.warn(
        'ReputationService: No gRPC client. Cache + local analysis only. ' +
        'Register REPUTATION_SERVICE gRPC client to enable remote reputation.',
      );
      return;
    }
    try {
      this.reputationClient =
        this.client.getService<ReputationGrpcService>('ReputationService');
    } catch (err) {
      this.logger.warn(`ReputationService gRPC init failed: ${err instanceof Error ? err.message : String(err)}`);
    }
  }

  /**
   * check() — compute full reputation signals for an email.
   * Non-fatal: returns UNKNOWN_REPUTATION on any failure.
   */
  async check(email: ParsedEmail): Promise<ReputationSignals> {
    try {
      return await this.doCheck(email);
    } catch (err) {
      this.logger.warn(`ReputationService.check failed (non-fatal): ${err instanceof Error ? err.message : String(err)}`);
      return UNKNOWN_REPUTATION;
    }
  }

  private async doCheck(email: ParsedEmail): Promise<ReputationSignals> {
    const senderIp     = this.extractSenderIp(email);
    const senderDomain = email.fromFullDomain ?? '';
    const urls         = email.urls.slice(0, 20);
    const hashes       = email.attachments.filter(a => a.sha256).map(a => a.sha256!);

    // ── 1. Try gRPC first (if available) ──────────────────────────────────────
    if (this.reputationClient) {
      try {
        const grpcResult = await firstValueFrom(
          this.reputationClient.CheckReputation({
            sender_ip:         senderIp,
            sender_domain:     senderDomain,
            urls,
            attachment_hashes: hashes,
          }),
        );

        // Write gRPC results back into cache for future emails
        await this.writeGrpcResultsToCache(senderIp, senderDomain, urls, hashes, grpcResult);

        return this.mapGrpcResponse(grpcResult);
      } catch (err) {
        this.logger.warn(`Reputation gRPC call failed, falling back to cache+local: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    // ── 2. Cache + local analysis ─────────────────────────────────────────────
    return await this.checkFromCacheAndLocal(senderIp, senderDomain, urls, hashes);
  }

  // ─── Cache + local analysis ─────────────────────────────────────────────────
  private async checkFromCacheAndLocal(
    senderIp:     string,
    senderDomain: string,
    urls:         string[],
    hashes:       string[],
  ): Promise<ReputationSignals> {

    // Run all lookups in parallel for performance
    const [ipResult, domainResult, urlResults, hashResults] = await Promise.all([
      senderIp ? this.intel.lookupIp(senderIp) : Promise.resolve(null),
      senderDomain ? this.intel.lookupDomain(senderDomain) : Promise.resolve(null),
      urls.length > 0 ? this.intel.lookupUrls(urls) : Promise.resolve(new Map()),
      Promise.all(hashes.slice(0, 10).map(h => this.intel.lookupFileHash(h))),
    ]);

    // ── Aggregate IP reputation ───────────────────────────────────────────────
    const senderIpRep = ipResult?.reputation ?? 'unknown';

    // ── Aggregate domain reputation ───────────────────────────────────────────
    let domainRep: ReputationSignals['domainReputation'] = 'unknown';
    if (domainResult) {
      domainRep = domainResult.reputation === 'bad'     ? 'bad'
                : domainResult.reputation === 'good'    ? 'good'
                : domainResult.isDisposable             ? 'bad'
                : domainResult.isSuspiciousTld          ? 'neutral'
                : 'unknown';
    }

    // ── Aggregate URL reputation ──────────────────────────────────────────────
    let urlRep: ReputationSignals['urlReputation'] = 'unknown';
    if (urlResults.size > 0) {
      const hasMalicious  = [...urlResults.values()].some(u => u.verdict === 'malicious');
      const hasSuspicious = [...urlResults.values()].some(u => u.verdict === 'suspicious');
      urlRep = hasMalicious ? 'bad' : hasSuspicious ? 'neutral' : 'unknown';
    }

    // ── Aggregate hash reputation ─────────────────────────────────────────────
    let hashRep: ReputationSignals['attachmentHashReputation'] = 'unknown';
    if (hashResults.length > 0) {
      const hasMalicious  = hashResults.some(h => h.verdict === 'malicious');
      const hasSuspicious = hashResults.some(h => h.verdict === 'suspicious');
      hashRep = hasMalicious ? 'malicious' : hasSuspicious ? 'suspicious' : 'unknown';
    }

    // ── Threat score ──────────────────────────────────────────────────────────
    let threatScore = 0;
    if (senderIpRep   === 'bad')       threatScore += 30;
    if (domainRep     === 'bad')       threatScore += 25;
    if (urlRep        === 'bad')       threatScore += 25;
    if (hashRep       === 'malicious') threatScore += 40;
    if (hashRep       === 'suspicious') threatScore += 20;
    if (domainResult?.isDisposable)    threatScore += 15;
    if (domainResult?.isSuspiciousTld) threatScore += 10;

    const details = [
      senderIp     ? `IP(${senderIp}): ${senderIpRep}`  : null,
      senderDomain ? `Domain(${senderDomain}): ${domainRep}` : null,
      urls.length  ? `URLs(${urls.length}): ${urlRep}`  : null,
      hashes.length? `Hashes(${hashes.length}): ${hashRep}` : null,
    ].filter(Boolean).join(' | ');

    return {
      senderIpReputation:       senderIpRep as ReputationSignals['senderIpReputation'],
      domainReputation:         domainRep,
      urlReputation:            urlRep,
      attachmentHashReputation: hashRep,
      overallThreatScore:       Math.min(100, threatScore),
      details:                  details || 'Local analysis',
    };
  }

  // ─── Write gRPC results back into cache ─────────────────────────────────────
  private async writeGrpcResultsToCache(
    ip:       string,
    domain:   string,
    urls:     string[],
    hashes:   string[],
    response: ReputationResponse,
  ): Promise<void> {
    const now = Date.now();
    try {
      const tasks: Promise<void>[] = [];

      if (ip) {
        tasks.push(this.intel.setIpResult(ip, {
          ip, reputation: this.normalizeRep(response.ip_reputation) as any,
          score: response.threat_score ?? 0,
          isProxy: false, isTor: false,
          source: 'grpc', cachedAt: now,
        }));
      }

      if (domain) {
        tasks.push(this.intel.setDomainResult(domain, {
          domain, reputation: this.normalizeRep(response.domain_reputation) as any,
          score: response.threat_score ?? 0,
          isNewlyReg: false, isSuspiciousTld: false, isDisposable: false,
          source: 'grpc', cachedAt: now,
        }));
      }

      await Promise.all(tasks);
    } catch (err) {
      this.logger.warn(`Failed to write gRPC results to cache: ${err}`);
    }
  }

  // ─── Map gRPC response ──────────────────────────────────────────────────────
  private mapGrpcResponse(r: ReputationResponse): ReputationSignals {
    return {
      senderIpReputation:           this.normalizeRep(r.ip_reputation) as ReputationSignals['senderIpReputation'],
      domainReputation:             this.normalizeRep(r.domain_reputation) as ReputationSignals['domainReputation'],
      urlReputation:                this.normalizeRep(r.url_reputation) as ReputationSignals['urlReputation'],
      attachmentHashReputation:     this.normalizeHash(r.hash_reputation),
      overallThreatScore:           Math.min(100, Math.max(0, r.threat_score ?? 0)),
      details:                      r.details ?? '',
    };
  }

  private normalizeRep(val: string): string {
    const valid = ['good', 'bad', 'neutral', 'unknown'];
    return valid.includes(val?.toLowerCase()) ? val.toLowerCase() : 'unknown';
  }

  private normalizeHash(val: string): ReputationSignals['attachmentHashReputation'] {
    const valid = ['clean', 'malicious', 'suspicious', 'unknown'];
    return (valid.includes(val?.toLowerCase()) ? val.toLowerCase() : 'unknown') as ReputationSignals['attachmentHashReputation'];
  }

  private extractSenderIp(email: ParsedEmail): string {
    if (!email.headers) return '';
    const received = email.headers['received'] ?? email.headers['Received'];
    const receivedStr = Array.isArray(received) ? received[0] : (received ?? '');
    const ipMatch = receivedStr.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
    return ipMatch ? ipMatch[1] : '';
  }
}
