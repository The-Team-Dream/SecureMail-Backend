// ─────────────────────────────────────────────────────────────────────────────
// security.service.ts  —  Security Pipeline Orchestrator
//
// This is the Brain Orchestrator for the entire security pipeline.
// It coordinates all 11 stages in the correct order:
//
//   1.  Email Parsing Engine
//   2.  Authentication Engine
//   3.  Reputation Engine
//   4.  Detection Rule Engine (delegates to ClassificationService)
//   5.  Rule Graph Amplification
//   6.  URL Analysis Engine
//   7.  Behavioral Analysis Engine
//   8.  Malware Analysis (existing MalwareService — reused)
//   9.  AI Security Agent (existing AiAgentService — reused)
//  10.  Correlation Engine
//  11.  Risk Scoring Engine
//  12.  Decision Engine
//  13.  Post-Delivery Protection (async, non-blocking)
//
// The existing email-sync.processor.ts classifyAndMove() remains INTACT.
// This service provides an ENHANCED pipeline for full-context analysis.
// New emails go through this service; the old path is preserved as fallback.
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable, Logger } from '@nestjs/common';
import { PrismaService }         from '../prisma.service';
import { MalwareService }        from '../malware/malware.service';
import { AiAgentService }        from '../ai-agent/ai-agent.service';
import { NotificationsService }  from '../notifications/notifications.service';
import { NotificationType, FolderType } from 'generated/prisma/enums';

import { EmailParserService, RawEmailInput, ParsedEmail } from './pipeline/email-parser/email-parser.service';
import { AuthenticationService }   from './pipeline/authentication/authentication.service';
import { ReputationService }       from './pipeline/reputation/reputation.service';
import { RuleEngineService }       from './pipeline/detection/rule-engine/rule-engine.service';
import { RuleGraphService }        from './pipeline/detection/rule-graph/rule-graph.service';
import { CorrelationService }      from './pipeline/detection/correlation-engine/correlation.service';
import { RuleRegistry }            from './pipeline/detection/rules/rule-registry.service';
import { UrlAnalysisService }      from './pipeline/url-analysis/url-analysis.service';
import { BehaviorService }         from './pipeline/behavior/behavior.service';
import { ScoringService }          from './pipeline/scoring/scoring.service';
import { DecisionService, FinalVerdict } from './pipeline/decision/decision.service';
import {
  DetectionContext,
  UNKNOWN_REPUTATION,
  DEFAULT_BEHAVIOR,
  MalwareSignals,
} from './pipeline/detection/rule-engine/detection-context';

// ─── Pipeline input ───────────────────────────────────────────────────────────
export interface SecurityPipelineInput extends RawEmailInput {
  // Attachments with storage paths (already persisted by email-sync processor)
  attachments?: Array<{
    filename:    string;
    mimeType:    string;
    size:        number;
    storagePath: string;
  }>;
}

// ─── Pipeline output ──────────────────────────────────────────────────────────
export interface SecurityPipelineResult {
  verdict:        FinalVerdict;
  parsedEmail:    ParsedEmail;
  authSummary:    string;
  riskAssessment?: object;
  ruleHits:       Array<{ rule: string; score: number; description: string }>;
  aiReport:       Record<string, unknown> | null;
  processingMs:   number;
}

@Injectable()
export class SecurityService {
  private readonly logger = new Logger(SecurityService.name);

  constructor(
    private readonly prisma:          PrismaService,
    private readonly malwareService:  MalwareService,
    private readonly aiAgentService:  AiAgentService,
    private readonly notifications:   NotificationsService,

    // Pipeline stages
    private readonly emailParser:     EmailParserService,
    private readonly authentication:  AuthenticationService,
    private readonly reputation:      ReputationService,
    private readonly ruleEngine:      RuleEngineService,
    private readonly ruleRegistry:    RuleRegistry,
    private readonly ruleGraph:       RuleGraphService,
    private readonly correlation:     CorrelationService,
    private readonly urlAnalysis:     UrlAnalysisService,
    private readonly behavior:        BehaviorService,
    private readonly scoring:         ScoringService,
    private readonly decision:        DecisionService,
  ) {}

  /**
   * analyze() — run the full security pipeline for an email.
   *
   * Designed to be called from email-sync.processor.ts as a drop-in
   * replacement for the existing classifyAndMove() method.
   */
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
        error:   err instanceof Error ? err.message : String(err),
        stack:   err instanceof Error ? err.stack : undefined,
      });

      // Fallback: return safe defaults so email processing continues
      return this.buildFallbackResult(input, startMs);
    }
  }

  // ─── Main pipeline ─────────────────────────────────────────────────────────
  private async runPipeline(
    input:   SecurityPipelineInput,
    userId:  number,
    startMs: number,
  ): Promise<SecurityPipelineResult> {

    // ── Stage 1: Email Parsing ────────────────────────────────────────────────
    const parsedEmail = this.emailParser.parse(input);

    // ── Stage 2: Authentication Analysis ─────────────────────────────────────
    const authResult = this.authentication.analyze(parsedEmail);

    // ── Stage 3: Reputation Check (non-blocking) ──────────────────────────────
    // Run in parallel with behavioral analysis
    const [reputationSignals, behaviorSignals] = await Promise.all([
      this.reputation.check(parsedEmail).catch(() => UNKNOWN_REPUTATION),
      this.behavior.analyze(parsedEmail).catch(() => DEFAULT_BEHAVIOR),
    ]);

    // ── Stage 4: Malware Analysis (parallel with URL analysis) ───────────────
    const [malwareSignals, urlAnalysisResult] = await Promise.all([
      this.runMalwareAnalysis(input),
      this.urlAnalysis.analyze(parsedEmail).catch(() => null),
    ]);

    // ── Stage 5: Build Detection Context ─────────────────────────────────────
    const ctx = new DetectionContext(
      parsedEmail,
      authResult,
      reputationSignals,
      behaviorSignals,
      malwareSignals,
    );

    // ── Stage 6: Rule Engine (ClassificationService + context rules) ──────────
    await this.ruleEngine.runAll(ctx);

    // ── Stage 7: Rule Graph Amplification ─────────────────────────────────────
    this.ruleGraph.applyGraphAmplification(ctx);

    // ── Stage 8: Correlation Engine ───────────────────────────────────────────
    const correlationResult = this.correlation.correlate(ctx);
    ctx.correlation = correlationResult;

    // ── Stage 9: Risk Scoring ─────────────────────────────────────────────────
    const riskAssessment = this.scoring.computeRisk(ctx, urlAnalysisResult ?? undefined);

    // ── Stage 10: AI Security Agent ───────────────────────────────────────────
    const aiReport = await this.runAiAgent(parsedEmail, ctx, riskAssessment);

    // ── Stage 11: Decision Engine ─────────────────────────────────────────────
    const verdict = this.decision.decide(riskAssessment, ctx, correlationResult);

    // ── Stage 12: Persist results to DB ──────────────────────────────────────
    await this.persistResults(input, riskAssessment, malwareSignals, aiReport, verdict);

    // ── Stage 13: Notifications ───────────────────────────────────────────────
    await this.sendNotifications(input, userId, verdict, riskAssessment, malwareSignals);

    const processingMs = Date.now() - startMs;

    this.logger.log('Security pipeline complete', {
      emailId:       input.emailId,
      verdict:       verdict.label,
      score:         riskAssessment.finalScore,
      processingMs,
      patterns:      correlationResult.patterns,
      triggeredRules: ctx.getTriggeredRuleIds().length,
    });

    return {
      verdict,
      parsedEmail,
      authSummary: authResult.summary,
      riskAssessment,
      ruleHits:    ctx.getTriggeredRules().map(r => ({
        rule:        r.ruleId,
        score:       r.score,
        description: r.explanation,
      })),
      aiReport:      aiReport as Record<string, unknown> | null,
      processingMs,
    };
  }

  // ─── Malware analysis (reuses existing MalwareService) ───────────────────
  private async runMalwareAnalysis(input: SecurityPipelineInput): Promise<MalwareSignals | null> {
    if (!input.attachments || input.attachments.length === 0) return null;

    let worstScore    = 0;
    let worstVerdict  = 'clean';
    let worstSeverity = 'Low';

    for (const att of input.attachments) {
      const result = await this.malwareService.analyzeFile({
        storagePath: att.storagePath,
        filename:    att.filename ?? 'unknown',
        mimeType:    att.mimeType,
      }).catch(() => null);

      if (result && result.score > worstScore) {
        worstScore    = result.score;
        worstVerdict  = result.verdict;
        worstSeverity = result.severity;
      }
    }

    return { verdict: worstVerdict, score: worstScore, severity: worstSeverity };
  }

  // ─── AI Agent (reuses existing AiAgentService) ────────────────────────────
  private async runAiAgent(
    parsedEmail:     ParsedEmail,
    ctx:             DetectionContext,
    riskAssessment:  { spamScore: number; phishingScore: number; isSpam: boolean; isPhishing: boolean },
  ): Promise<unknown> {
    try {
      return await this.aiAgentService.generateReport({
        emailId:     parsedEmail.emailId,
        subject:     parsedEmail.subject,
        fromAddr:    parsedEmail.fromAddr,
        fromName:    parsedEmail.fromName ?? '',
        bodyText:    parsedEmail.bodyPlain,

        spamScore:     riskAssessment.spamScore,
        phishingScore: riskAssessment.phishingScore,
        isSpam:        riskAssessment.isSpam,
        isPhishing:    riskAssessment.isPhishing,

        ruleHits: ctx.getTriggeredRules().map(r => ({
          rule:        r.ruleId,
          score:       r.score,
          description: r.explanation,
        })),

        hasAttachment:   parsedEmail.hasAttachment,
        malwareVerdict:  ctx.malware?.verdict  ?? '',
        malwareScore:    ctx.malware?.score    ?? 0,
        malwareSeverity: ctx.malware?.severity ?? '',

        mailboxId:           parsedEmail.mailBoxId,
        previousEmailCount:  ctx.behavior.previousEmailCount,
        senderTypicalTopic:  ctx.behavior.typicalTopic,
      });
    } catch {
      return null; // AI agent is non-fatal
    }
  }

  // ─── Persist results ──────────────────────────────────────────────────────
  private async persistResults(
    input:          SecurityPipelineInput,
    risk:           { spamScore: number; phishingScore: number; isSpam: boolean; isPhishing: boolean; isMalware: boolean; finalScore: number },
    malware:        MalwareSignals | null,
    aiReport:       unknown,
    verdict:        FinalVerdict,
  ): Promise<void> {
    const emailId = Number(input.emailId);
    if (!emailId || isNaN(emailId)) return;

    const updateData: Record<string, unknown> = {
      spamScore:      risk.spamScore,
      phishingScore:  risk.phishingScore,
      isSpam:         risk.isSpam && !risk.isPhishing && !risk.isMalware,
      isPhishing:     risk.isPhishing && !risk.isMalware,
      malwareScore:   malware?.score    ?? null,
      malwareVerdict: malware?.verdict  ?? null,
      malwareSeverity: malware?.severity ?? null,
      aiReport:       aiReport ?? null,
    };

    // Move to appropriate folder
    let targetFolderType: FolderType | null = null;
    if (risk.isMalware)         targetFolderType = FolderType.MALWARE;
    else if (risk.isPhishing)   targetFolderType = FolderType.PHISHING;
    else if (risk.isSpam)       targetFolderType = FolderType.SPAM;

    if (targetFolderType) {
      const folder = await this.getOrCreateFolder(Number(input.mailBoxId), targetFolderType);
      updateData.folderId = folder.id;
    }

    await this.prisma.email.update({
      where: { id: emailId },
      data:  updateData,
    }).catch(err => this.logger.warn('Email update failed', { emailId, error: String(err) }));
  }

  // ─── Notifications ────────────────────────────────────────────────────────
  private async sendNotifications(
    input:   SecurityPipelineInput,
    userId:  number,
    verdict: FinalVerdict,
    risk:    { isMalware: boolean; isPhishing: boolean; finalScore: number },
    malware: MalwareSignals | null,
  ): Promise<void> {
    const emailId   = Number(input.emailId);
    const mailBoxId = Number(input.mailBoxId);
    const subject   = input.subject || '(No subject)';

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

  // ─── Folder helper ────────────────────────────────────────────────────────
  private async getOrCreateFolder(mailBoxId: number, type: FolderType) {
    let folder = await this.prisma.folder.findFirst({ where: { mailBoxId, type } });
    if (!folder) {
      folder = await this.prisma.folder.create({
        data: { mailBoxId, name: type.toLowerCase(), type, remoteId: type },
      });
    }
    return folder;
  }

  // ─── Fallback result ──────────────────────────────────────────────────────
  private buildFallbackResult(
    input:   SecurityPipelineInput,
    startMs: number,
  ): SecurityPipelineResult {
    return {
      verdict: {
        label:           'SAFE',
        riskScore:       0,
        confidence:      0,
        action:          'allow',
        explanation:     'Security pipeline error — email delivered with no analysis.',
        details:         [],
        triggeredRules:  [],
        attackPatterns:  [],
        recommendations: [],
      },
      parsedEmail:  this.emailParser.parse(input),
      authSummary:  'unknown',
      ruleHits:     [],
      aiReport:     null,
      processingMs: Date.now() - startMs,
    };
  }
}
