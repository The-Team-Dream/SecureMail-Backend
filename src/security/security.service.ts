import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { MalwareService } from './pipeline/6-malware/malware.service';
import type { MalwarePipelinePack } from './pipeline/6-malware/malware.types';
import {
    scanFileResponseToSignals,
    attachMalwareOkIntegrationMeta,
    failedMalwareIntegrationPayload,
} from './pipeline/6-malware/malware.mapping';
import { AiAgentService } from './pipeline/10-ai-agent/ai-agent.service';
import {
    analysisReportToAiSignals,
    attachOkIntegrationMeta,
    failedIntegrationPayload,
} from './pipeline/10-ai-agent/ai-agent.mapping';
import { NotificationsService } from '../notifications/notifications.service';
import { NotificationType, FolderType } from '@prisma/client';

import { AuthenticationService } from './pipeline/2-authentication/authentication.service';
import { ReputationService } from './pipeline/3-reputation/reputation.service';
import { RuleEngineService } from './pipeline/7-detection/rule-engine/rule-engine.service';
import { RuleGraphService } from './pipeline/7-detection/rule-graph/rule-graph.service';
import { CorrelationService } from './pipeline/7-detection/correlation-engine/correlation.service';
import { RuleRegistry } from './pipeline/7-detection/rules/rule-registry.service';
import { UrlAnalysisService } from './pipeline/5-url-analysis/url-analysis.service';
import { BehaviorService } from './pipeline/4-behavior/behavior.service';
import { ScoringService } from './pipeline/8-scoring/scoring.service';
import { DecisionService } from './pipeline/9-decision/decision.service';
import { DetectionContext, } from './pipeline/7-detection/rule-engine/detection-context';
import {
  AiIntegrationFailureKind,
  AiSignals,
  FinalVerdict,
  MalwareSignals,
  ParsedEmail,
  RawEmailInput,
} from 'src/security/types';
import { EmailParserService } from './pipeline/1-email-parser/email-parser.service';
import { DEFAULT_BEHAVIOR, UNKNOWN_REPUTATION } from 'src/security/constants';

export interface SecurityPipelineInput extends RawEmailInput { }

export interface SecurityPipelineResult {
  parsedEmail: ParsedEmail;
  verdict: FinalVerdict;
  riskAssessment: object;
  authSummary: string;
  ruleHits: Array<{ rule: string; score: number; description: string }>;
  aiReport: Record<string, unknown> | null;
  processingMs: number;
  malwareScan: Record<string, unknown>;
}

@Injectable()
export class SecurityService {
  private readonly logger = new Logger(SecurityService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly malwareService: MalwareService,
    private readonly aiAgentService: AiAgentService,
    private readonly notifications: NotificationsService,
    private readonly emailParser: EmailParserService,
    private readonly authentication: AuthenticationService,
    private readonly reputation: ReputationService,
    private readonly ruleEngine: RuleEngineService,
    private readonly ruleRegistry: RuleRegistry,
    private readonly ruleGraph: RuleGraphService,
    private readonly correlation: CorrelationService,
    private readonly urlAnalysis: UrlAnalysisService,
    private readonly behavior: BehaviorService,
    private readonly scoring: ScoringService,
    private readonly decision: DecisionService,
  ) { }

  async analyze(
    input: SecurityPipelineInput,
    userId: number,
  ): Promise<SecurityPipelineResult> {
    const startMs = Date.now();

    try {
      return await this.runPipeline(input, userId, startMs);
    } catch (err) {
      this.logger.error('SecurityPipeline.analyze failed', {
        emailId: input.emailId,
        error: err instanceof Error ? err.message : String(err),
        stack: err instanceof Error ? err.stack : undefined,
      });

      // Fallback: return safe defaults so email processing continues
      return this.buildFallbackResult(input, startMs);
    }
  }

  private async runPipeline(
    input: SecurityPipelineInput,
    userId: number,
    startMs: number,
  ): Promise<SecurityPipelineResult> {

    const parsedEmail = this.emailParser.parse(input);

    const malwarePromise = this.runMalwareScan(input);
    const [authSignals, reputationSignals, behaviorSignals, urlAnalysisSignals, malwareRace] = await Promise.all([
      this.authentication.analyze(parsedEmail),
      this.reputation.check(parsedEmail).catch(() => UNKNOWN_REPUTATION),
      this.behavior.analyze(parsedEmail).catch(() => DEFAULT_BEHAVIOR),
      this.urlAnalysis.analyze(parsedEmail).catch(() => null),
      Promise.race([
        malwarePromise,
        new Promise<'timeout'>(r => setTimeout(() => r('timeout'), 5000)),
      ]),
    ]);

    let malwarePack: MalwarePipelinePack;
    if (malwareRace === 'timeout') {
      if (!input.attachments?.length) {
        malwarePack = await malwarePromise;
      } else {
        malwarePack = {
          signals: null,
          integration: {
            state: 'failed',
            atMs: Date.now(),
            kind: 'deadline',
            message: 'Malware scan exceeded synchronous pipeline window (5s)',
          },
        };
      }
    } else {
      malwarePack = malwareRace;
    }

    const ctx = new DetectionContext(
      parsedEmail,
      authSignals,
      reputationSignals,
      behaviorSignals,
      urlAnalysisSignals,
      malwarePack.signals,
      malwarePack.integration,
    );
    await this.ruleEngine.runRuleEngine(ctx);

    await this.ruleGraph.applyGraphAmplification(ctx);

    ctx.setCorrelation(await this.correlation.correlate(ctx));

    ctx.setRiskAssessment(this.scoring.computeRisk(ctx));
    if (!ctx.riskAssessment) {
      this.logger.error('Scoring failed — aborting pipeline');
      return this.buildFallbackResult(input, startMs);
    }

    ctx.setVerdict(this.decision.decide(ctx.riskAssessment!, ctx));
    if (!ctx.verdict) {
      this.logger.error('Decision failed — aborting pipeline');
      return this.buildFallbackResult(input, startMs);
    }

    ctx.setAiReport(await this.runAiAgent(ctx));

    await this.persistResults(input, ctx);

    await this.sendNotifications(input, userId, ctx);

    // If malware scanning still running after sync window, finish in background (late malicious verdict)
    if (malwareRace === 'timeout' && input.attachments?.length) {
      malwarePromise
        .then(async pack => {
          const sig = pack.signals;
          if (!sig || sig.verdict !== 'malicious') return;
          const emailId = Number(input.emailId);
          const mailBoxId = Number(input.mailBoxId);
          const folder = await this.getOrCreateFolder(mailBoxId, FolderType.MALWARE);
          await this.prisma.email.update({
            where: { id: emailId },
            data: {
              malwareScore: sig.score ?? 0,
              malwareVerdict: sig.verdict,
              malwareSeverity: sig.severity ?? 'Critical',
              isPhishing: false,
              isSpam: false,
              folderId: folder.id,
            },
          });
          await this.notify(
            userId,
            mailBoxId,
            emailId,
            NotificationType.MALWARE_DETECTED,
            'Malware Detected',
            `Malicious attachment detected in: ${input.subject}`,
            { emailId, malwareScore: sig.score, malwareVerdict: sig.verdict },
          );

          this.logger.warn('Post-delivery malware detected', {
            emailId,
            score: sig.score,
            verdict: sig.verdict,
            integration: pack.integration,
          });
        })
        .catch(err => {
          this.logger.warn('Background malware completion failed', {
            emailId: input.emailId,
            error: err instanceof Error ? err.message : String(err),
          });
        });
    }

    const processingMs = Date.now() - startMs;

    this.logger.log('Security pipeline complete', {
      emailId: input.emailId,
      verdict: ctx.verdict!.label,
      score: ctx.riskAssessment!.finalScore,
      processingMs,
      patterns: ctx.correlation.patterns,
      triggeredRules: ctx.getTriggeredRuleIds().length,
    });

    return {
      parsedEmail: ctx.parsedEmail,
      riskAssessment: ctx.riskAssessment,
      verdict: ctx.verdict!,
      authSummary: ctx.authResult.summary,
      ruleHits: ctx.getTriggeredRules().map(r => ({
        rule: r.ruleId,
        score: r.originalScore + r.amplifiedScore,
        description: r.explanation,
      })),
      aiReport: this.buildAiReportSnapshot(ctx),
      processingMs,
      malwareScan: this.buildMalwareScanSnapshot(ctx, input),
    };
  }

  private buildMalwareScanSnapshot(
    ctx: DetectionContext,
    input: SecurityPipelineInput,
  ): Record<string, unknown> {
    if (ctx.malwareIntegration.state === 'ok' && ctx.malware) {
      return attachMalwareOkIntegrationMeta(ctx.malware, ctx.malwareIntegration);
    }
    if (ctx.malwareIntegration.state === 'failed') {
      const base = failedMalwareIntegrationPayload(ctx.malwareIntegration);
      if (ctx.malwareIntegration.kind === 'deadline' && input.attachments?.length) {
        return {
          ...base,
          message:
            'Malware scan still running — you will be notified if a threat is found',
          status: 'pending',
        };
      }
      return base;
    }
    if (!input.attachments?.length) {
      return {
        __integration: ctx.malwareIntegration,
        status: 'not_applicable',
        message: 'No attachments',
      };
    }
    return {
      __integration: ctx.malwareIntegration,
      status: 'not_applicable',
      message: 'Malware scan not available',
    };
  }

  private buildAiReportSnapshot(ctx: DetectionContext): Record<string, unknown> | null {
    if (ctx.aiIntegration.state === 'ok' && Object.keys(ctx.ai).length > 0) {
      return attachOkIntegrationMeta(ctx.ai, ctx.aiIntegration) as Record<string, unknown>;
    }
    if (ctx.aiIntegration.state === 'failed') {
      return failedIntegrationPayload(ctx.aiIntegration) as Record<string, unknown>;
    }
    return null;
  }

  private mergeMalwareSignals(a: MalwareSignals, b: MalwareSignals): MalwareSignals {
    const sa = a.score ?? 0;
    const sb = b.score ?? 0;
    return sa >= sb ? a : b;
  }

  /** Aggregates per-attachment scans into pipeline pack + integration metadata. */
  private async runMalwareScan(input: SecurityPipelineInput): Promise<MalwarePipelinePack> {
    const started = Date.now();
    const atMs = Date.now();
    if (!input.attachments?.length) {
      return { signals: null, integration: { state: 'skipped', atMs } };
    }

    let merged: MalwareSignals | null = null;
    let okCount = 0;
    let failFirst: { message: string; grpcCode?: number; kind: AiIntegrationFailureKind } | null = null;

    for (const att of input.attachments) {
      const outcome = await this.malwareService.scanFile({
        storagePath: att.storagePath,
        filename: att.filename ?? 'unknown',
        mimeType: att.mimeType ?? 'application/octet-stream',
      });
      if (outcome.ok) {
        okCount += 1;
        const sig = scanFileResponseToSignals(outcome.report);
        merged = merged ? this.mergeMalwareSignals(merged, sig) : sig;
      } else if (!failFirst) {
        failFirst = outcome.error;
      }
    }

    const wallMs = Date.now() - started;

    if (okCount === 0 && failFirst) {
      return {
        signals: null,
        integration: {
          state: 'failed',
          atMs: Date.now(),
          grpcCode: failFirst.grpcCode,
          message: failFirst.message,
          kind: failFirst.kind,
          latencyMs: wallMs,
        },
      };
    }

    const partialNote =
      okCount < input.attachments.length && failFirst
        ? `partial: ${okCount}/${input.attachments.length} attachments scanned`
        : undefined;
    if (partialNote && failFirst) {
      this.logger.warn(`Malware scan partial success: ${partialNote}; firstError=${failFirst.message}`);
    }

    return {
      signals: merged,
      integration: {
        state: 'ok',
        atMs: Date.now(),
        latencyMs: wallMs,
        engineLatencyMs: merged?.scanTimeMs,
        ...(partialNote ? { message: partialNote } : {}),
      },
    };
  }

  private async runAiAgent(ctx: DetectionContext): Promise<AiSignals> {
    const risk = ctx.riskAssessment!;
    const email = ctx.parsedEmail;
    const outcome = await this.aiAgentService.generateReport({
      emailId: email.emailId,
      subject: email.subject,
      fromAddr: email.fromAddr,
      fromName: email.fromName ?? '',
      bodyText: email.bodyPlain,

      spamScore: risk.spamScore,
      phishingScore: risk.phishingScore,
      isSpam: risk.isSpam,
      isPhishing: risk.isPhishing,

      ruleHits: ctx.getTriggeredRules().map(r => ({
        rule: r.ruleId,
        score: r.originalScore + r.amplifiedScore,
        description: r.explanation,
      })),

      hasAttachment: email.hasAttachment,
      malwareVerdict: ctx.malware?.verdict ?? '',
      malwareScore: ctx.malware?.score ?? 0,
      malwareSeverity: ctx.malware?.severity ?? '',

      mailboxId: email.mailBoxId,
      previousEmailCount: ctx.behavior.previousEmailCount,
      senderTypicalTopic: ctx.behavior.typicalTopic,
    });

    const atMs = Date.now();
    if (outcome.ok) {
      ctx.setAiIntegration({ state: 'ok', atMs });
      return analysisReportToAiSignals(outcome.report);
    }
    ctx.setAiIntegration({
      state: 'failed',
      atMs,
      grpcCode: outcome.error.grpcCode,
      message: outcome.error.message,
      kind: outcome.error.kind,
    });
    return {};
  }

  private async persistResults(
    input: SecurityPipelineInput,
    ctx: DetectionContext,
  ): Promise<void> {
    const emailId = Number(input.emailId);
    if (!emailId || isNaN(emailId)) return;

    const risk = ctx.riskAssessment!;
    const malware = ctx.malware;

    const aiReport =
      ctx.aiIntegration.state === 'ok' && Object.keys(ctx.ai).length > 0
        ? attachOkIntegrationMeta(ctx.ai, ctx.aiIntegration)
        : ctx.aiIntegration.state === 'failed'
          ? failedIntegrationPayload(ctx.aiIntegration)
          : null;

    const updateData: Record<string, unknown> = {
      spamScore: risk.spamScore,
      phishingScore: risk.phishingScore,
      isSpam: risk.isSpam && !risk.isPhishing && !risk.isMalware,
      isPhishing: risk.isPhishing && !risk.isMalware,
      malwareScore: malware?.score ?? null,
      malwareVerdict: malware?.verdict ?? null,
      malwareSeverity: malware?.severity ?? null,
      aiReport,
    };

    // Move to appropriate folder
    let targetFolderType: FolderType | null = null;
    if (risk.isMalware) targetFolderType = FolderType.MALWARE;
    else if (risk.isPhishing) targetFolderType = FolderType.PHISHING;
    else if (risk.isSpam) targetFolderType = FolderType.SPAM;

    if (targetFolderType) {
      const folder = await this.getOrCreateFolder(Number(input.mailBoxId), targetFolderType);
      updateData.folderId = folder.id;
    }

    await this.prisma.email.update({
      where: { id: emailId },
      data: updateData,
    }).catch(err => this.logger.warn('Email update failed', { emailId, error: String(err) }));
  }

  private async sendNotifications(
    input: SecurityPipelineInput,
    userId: number,
    ctx: DetectionContext,
  ): Promise<void> {
    const emailId = Number(input.emailId);
    const mailBoxId = Number(input.mailBoxId);
    const subject = input.subject || '(No subject)';
    const risk = ctx.riskAssessment!;
    const verdict = ctx.verdict!;
    const malware = ctx.malware;

    if (risk.isMalware) {
      await this.notify(userId, mailBoxId, emailId, NotificationType.MALWARE_DETECTED,
        'Malware Detected',
        `Malicious attachment detected in: ${subject}`,
        { emailId, malwareVerdict: malware?.verdict, malwareScore: malware?.score },
      );
    } else if (risk.isPhishing) {
      const title = verdict.attackPatterns.length > 0
        ? `🚨 ${verdict.attackPatterns[0].replace(/_/g, ' ').toUpperCase()} Detected`
        : 'Phishing Detected';

      await this.notify(userId, mailBoxId, emailId, NotificationType.PHISHING_DETECTED,
        title,
        verdict.explanation,
        { emailId, patterns: verdict.attackPatterns, riskScore: risk.finalScore },
      );
    }
  }

  private async notify(
    userId: number, mailBoxId: number, emailId: number,
    type: NotificationType, title: string, message: string, metadata: Record<string, unknown>,
  ): Promise<void> {
    try {
      await this.notifications.create({ userId, type, title, message, metadata, mailBoxId, emailId });
    } catch { /* non-fatal */ }
  }

  private async getOrCreateFolder(mailBoxId: number, type: FolderType) {
    let folder = await this.prisma.folder.findFirst({ where: { mailBoxId, type } });
    if (!folder) {
      folder = await this.prisma.folder.create({
        data: { mailBoxId, name: type.toLowerCase(), type, remoteId: type },
      });
    }
    return folder;
  }

  private buildFallbackResult(
    input: SecurityPipelineInput,
    startMs: number,
  ): SecurityPipelineResult {
    return {
      verdict: {
        label: 'SAFE',
        riskScore: 0,
        confidence: 0,
        action: 'allow',
        explanation: 'Security pipeline error — email delivered with no analysis.',
        details: [],
        triggeredRules: [],
        attackPatterns: [],
        recommendations: [],
      },
      riskAssessment: [],
      parsedEmail: this.emailParser.parse(input),
      authSummary: 'unknown',
      ruleHits: [],
      aiReport: null,
      processingMs: Date.now() - startMs,
      malwareScan: failedMalwareIntegrationPayload({
        state: 'failed',
        atMs: Date.now(),
        kind: 'internal',
        message: 'Security pipeline error — malware scan unavailable',
      }),
    };
  }
}
