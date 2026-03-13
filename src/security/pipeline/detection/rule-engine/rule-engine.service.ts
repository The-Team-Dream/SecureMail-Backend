// ─────────────────────────────────────────────────────────────────────────────
// detection/rule-engine/rule-engine.service.ts
//
// Detection Rule Engine — Stage 4 of the Security Pipeline.
//
// Architecture (from guide):
//   "Instead of if statements, use Plugin Rule System"
//
// This service orchestrates rule evaluation in two phases:
//
//   Phase 1 — ClassificationService (existing battle-tested rules)
//             Maps results into the DetectionContext via RuleResult objects.
//
//   Phase 2 — RuleRegistry (new plugin rules)
//             Evaluates context-aware rules that require auth/rep/behavior signals.
//
// The two phases are additive — results accumulate in the same context.
// Score deduplication prevents double-counting overlapping rules.
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable, Logger } from '@nestjs/common';
import { ClassificationService } from '../../../../classification/classification.service';
import { RuleRegistry } from '../rules/rule-registry.service';
import { DetectionContext, RuleResult } from './detection-context';

@Injectable()
export class RuleEngineService {
  private readonly logger = new Logger(RuleEngineService.name);

  constructor(
    private readonly classificationService: ClassificationService,
    private readonly ruleRegistry: RuleRegistry,
  ) { }

  /**
   * runAll() — execute the complete rule pipeline.
   *
   * Phase 1: ClassificationService (26 battle-tested rules)
   * Phase 2: RuleRegistry plugins (context-aware, structured rules)
   * Phase 3: Context-level signals (auth failure, reputation threat, behavior)
   */
  async runAll(ctx: DetectionContext): Promise<void> {
    // ── Phase 1: Existing ClassificationService ──────────────────────────────
    await this.runClassificationPhase(ctx);

    // ── Phase 2: Plugin Rule Registry ────────────────────────────────────────
    await this.runPluginPhase(ctx);

    // ── Phase 3: Context-level signals ───────────────────────────────────────
    this.runContextPhase(ctx);
  }

  // ─── Phase 1: ClassificationService ───────────────────────────────────────
  private async runClassificationPhase(ctx: DetectionContext): Promise<void> {
    const email = ctx.parsedEmail;
    try {
      const result = await this.classificationService.classify({
        subject: email.subject,
        fromAddr: email.fromAddr,
        fromName: email.fromName ?? undefined,
        replyTo: email.replyTo,
        bodyText: email.bodyText,
        bodyHtml: email.bodyHtml,
        headers: email.headers,
        attachments: email.attachments.map(a => ({ filename: a.filename, mimeType: a.mimeType })),
        mailBoxId: email.mailBoxId,
      });

      // Map ruleHits → RuleResult objects in DetectionContext
      for (const hit of result.ruleHits) {
        if (ctx.ruleResults.has(hit.rule)) continue; // don't overwrite plugin result

        ctx.addResult({
          ruleId: hit.rule,
          category: this.inferCategory(hit.rule),
          severity: this.inferSeverity(hit.score),
          triggered: true,
          score: hit.score,
          confidence: 70,
          explanation: hit.description,
        });
      }

      // Base scores from ClassificationService (will be augmented by Phase 2+3)
      ctx.spamScore = result.spamScore;
      ctx.phishingScore = result.phishingScore;

    } catch (err) {
      this.logger.error('Phase 1 (ClassificationService) failed', {
        emailId: email.emailId,
        error: err instanceof Error ? err.message : String(err),
      });
    }
  }

  // ─── Phase 2: Plugin Rule Registry ────────────────────────────────────────
  // Evaluates only rules whose IDs are NOT already in the context
  // (avoids double-counting with ClassificationService)
  private async runPluginPhase(ctx: DetectionContext): Promise<void> {
    const allRules = this.ruleRegistry.getAll();
    const newRules = allRules.filter(r => !ctx.ruleResults.has(r.id));

    for (const rule of newRules) {
      if (rule.dependsOn?.some(dep => !ctx.isTriggered(dep))) continue;

      let result: RuleResult;
      try {
        result = await rule.evaluate(ctx);
      } catch (err) {
        this.logger.warn(`Plugin rule "${rule.id}" failed`, {
          error: err instanceof Error ? err.message : String(err),
        });
        continue;
      }

      ctx.addResult(result);
      if (!result.triggered) continue;

      if (rule.scoreTarget === 'phishing' || rule.scoreTarget === 'both') {
        ctx.phishingScore = Math.min(100, ctx.phishingScore + result.score);
      }
      if (rule.scoreTarget === 'spam' || rule.scoreTarget === 'both') {
        ctx.spamScore = Math.min(100, ctx.spamScore + result.score);
      }
    }
  }

  // ─── Phase 3: Context-level signals ───────────────────────────────────────
  // Signals that require the full context (auth, reputation, behavior)
  // and are NOT covered by any rule in the registry
  private runContextPhase(ctx: DetectionContext): void {

    // Auth failure enrichment (structured, beyond what domain.rules.ts provides)
    if (ctx.authResult.hasAuthFailure && !ctx.ruleResults.has('email_auth_failure')) {
      const score = { critical: 40, high: 30, medium: 20, low: 10, none: 0 }[ctx.authResult.failureSeverity] ?? 0;
      if (score > 0) {
        ctx.addResult({
          ruleId: 'email_auth_failure_enriched',
          category: 'authentication',
          severity: 'high',
          triggered: true,
          score,
          confidence: 90,
          explanation: `Auth failure [${ctx.authResult.summary}] — severity: ${ctx.authResult.failureSeverity}`,
        });
        ctx.phishingScore = Math.min(100, ctx.phishingScore + score);
      }
    }

    // Reputation threat
    if (ctx.reputation.senderIpReputation === 'bad' || ctx.reputation.domainReputation === 'bad') {
      const score = Math.min(40, ctx.reputation.overallThreatScore);
      if (score > 0) {
        ctx.addResult({
          ruleId: 'reputation_threat_signal',
          category: 'reputation',
          severity: 'high',
          triggered: true,
          score,
          confidence: 85,
          explanation: `Sender IP/domain has bad reputation: ${ctx.reputation.details}`,
        });
        ctx.phishingScore = Math.min(100, ctx.phishingScore + score);
      }
    }

    // Behavioral anomaly
    const authFullyPassed = ctx.authResult.spf.status === 'pass'
      && ctx.authResult.dkim.status === 'pass'
      && ctx.authResult.dmarc.status === 'pass'

    if (ctx.behavior.anomalyFlag && ctx.behavior.behaviorScore > 0 && !authFullyPassed) {
      const score = Math.min(25, ctx.behavior.behaviorScore);
      ctx.addResult({
        ruleId: 'behavioral_anomaly_detected',
        category: 'behavioral',
        severity: ctx.behavior.behaviorScore >= 50 ? 'high' : 'medium',
        triggered: true,
        score,
        confidence: 75,
        explanation: ctx.behavior.anomalyDescription || 'Behavioral anomaly detected',
      });
      ctx.phishingScore = Math.min(100, ctx.phishingScore + score);
    }

    // Malware + phishing amplification
    if (ctx.malware?.verdict === 'malicious' && ctx.phishingScore >= 20) {
      const amp = 20;
      ctx.addResult({
        ruleId: 'malware_phishing_combo',
        category: 'attachment',
        severity: 'critical',
        triggered: true,
        score: amp,
        confidence: 95,
        explanation: `Malicious attachment (score=${ctx.malware.score}) combined with phishing signals amplifies risk`,
      });
      ctx.phishingScore = Math.min(100, ctx.phishingScore + amp);
    }
  }

  // ─── Helpers ──────────────────────────────────────────────────────────────
  private inferCategory(ruleId: string): RuleResult['category'] {
    if (/auth|spf|dkim|dmarc|arc/.test(ruleId)) return 'authentication';
    if (/url|link|base64|ip_based|shortened|obfusca/.test(ruleId)) return 'url';
    if (/sender|reply|display_name|first_contact|disposable/.test(ruleId)) return 'sender';
    if (/header|received|conversation/.test(ruleId)) return 'headers';
    if (/attachment|malware|risky/.test(ruleId)) return 'attachment';
    if (/domain|spoof|homoglyph|tld|typo|lookalike/.test(ruleId)) return 'advanced';
    return 'content';
  }

  private inferSeverity(score: number): RuleResult['severity'] {
    if (score >= 35) return 'high';
    if (score >= 20) return 'medium';
    if (score >= 10) return 'low';
    return 'info';
  }
}
