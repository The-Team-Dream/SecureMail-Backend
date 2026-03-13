// ─────────────────────────────────────────────────────────────────────────────
// detection/rules/rule-registry.service.ts
//
// RuleRegistry — manages all DetectionRule plugin instances.
//
// Architecture (from guide):
//   "Plugin Rule System — rules loaded into a registry at startup"
//
// The registry:
//   1. Instantiates all built-in rules on module init
//   2. Evaluates them in dependency order
//   3. Writes results into the DetectionContext
//   4. Supports runtime rule addition (YAML DSL integration)
//
// This decouples the RuleEngine from individual rule logic entirely.
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { DetectionRule } from './detection-rule.interface';
import { DetectionContext, RuleResult } from '../rule-engine/detection-context';

// ── Sender rules
import {
  SenderDisplayNameMismatchRule,
  DisplayNameImpersonationRule,
  DisposableDomainRule,
  ReplyToDomainMismatchRule,
  FirstContactRiskRule,
} from './sender/sender-detection.rules';

// ── Content rules
import {
  UrgentPhishingLanguageRule,
  BECLanguageRule,
  CredentialHarvestingRule,
  ExcessiveCapitalizationRule,
  ExcessiveExclamationRule,
  RiskyAttachmentRule,
} from './content/content-detection.rules';

// ── Advanced rules
import {
  ConversationHijackingRule,
  HomoglyphDomainSpoofingRule,
  LookalikeDomainRule,
  BrandAbuseRule,
  HTMLObfuscationRule,
  Base64EncodedUrlRule,
} from './advanced/advanced-detection.rules';

@Injectable()
export class RuleRegistry implements OnModuleInit {
  private readonly logger  = new Logger(RuleRegistry.name);
  private readonly rules: DetectionRule[] = [];

  onModuleInit(): void {
    this.registerBuiltins();
    this.logger.log(
      `RuleRegistry initialized: ${this.rules.length} rules loaded ` +
      `[${[...new Set(this.rules.map(r => r.category))].join(', ')}]`,
    );
  }

  // ─── Register all built-in rule instances ──────────────────────────────────
  private registerBuiltins(): void {
    // Sender rules
    this.register(new SenderDisplayNameMismatchRule());
    this.register(new DisplayNameImpersonationRule());
    this.register(new DisposableDomainRule());
    this.register(new ReplyToDomainMismatchRule());
    this.register(new FirstContactRiskRule());

    // Content rules
    this.register(new UrgentPhishingLanguageRule());
    this.register(new BECLanguageRule());
    this.register(new CredentialHarvestingRule());
    this.register(new ExcessiveCapitalizationRule());
    this.register(new ExcessiveExclamationRule());
    this.register(new RiskyAttachmentRule());

    // Advanced attack rules
    this.register(new ConversationHijackingRule());
    this.register(new HomoglyphDomainSpoofingRule());
    this.register(new LookalikeDomainRule());
    this.register(new BrandAbuseRule());
    this.register(new HTMLObfuscationRule());
    this.register(new Base64EncodedUrlRule());
  }

  // ─── Public API ────────────────────────────────────────────────────────────

  /** Register a single rule — also used for runtime/YAML-loaded rules */
  register(rule: DetectionRule): void {
    if (this.rules.find(r => r.id === rule.id)) {
      this.logger.warn(`RuleRegistry: duplicate rule id "${rule.id}" — skipping`);
      return;
    }
    this.rules.push(rule);
  }

  /** Get all registered rules */
  getAll(): DetectionRule[] {
    return this.rules;
  }

  /** Get rules by category */
  getByCategory(category: DetectionRule['category']): DetectionRule[] {
    return this.rules.filter(r => r.category === category);
  }

  /**
   * evaluateAll() — run every registered rule against a DetectionContext.
   *
   * Rules are evaluated in dependency order:
   *   1. Rules with no dependencies first
   *   2. Rules whose dependencies have already been evaluated
   *
   * Results are written directly into the DetectionContext.
   * Score accumulators (spamScore, phishingScore) are updated per rule hit.
   */
  async evaluateAll(ctx: DetectionContext): Promise<void> {
    const ordered = this.resolveOrder();

    for (const rule of ordered) {
      // Skip if dependencies not met
      if (rule.dependsOn?.some(dep => !ctx.isTriggered(dep))) continue;

      let result: RuleResult;
      try {
        result = await rule.evaluate(ctx);
      } catch (err) {
        this.logger.error(`Rule "${rule.id}" evaluation failed`, {
          error: err instanceof Error ? err.message : String(err),
        });
        continue;
      }

      ctx.addResult(result);

      if (!result.triggered) continue;

      // Apply corroboration penalty (single high-weight rule with no support)
      const effectiveScore = this.applyCorroborationPenalty(rule, result, ctx);

      // Route score to correct bucket
      if (rule.scoreTarget === 'phishing' || rule.scoreTarget === 'both') {
        ctx.phishingScore = Math.min(100, ctx.phishingScore + effectiveScore);
      }
      if (rule.scoreTarget === 'spam' || rule.scoreTarget === 'both') {
        ctx.spamScore = Math.min(100, ctx.spamScore + effectiveScore);
      }
    }
  }

  // ─── Corroboration penalty ─────────────────────────────────────────────────
  // Rules with minCorroboration > 0 are weakened if they fire alone.
  // Once 2+ rules fire together, they apply at full weight.
  private applyCorroborationPenalty(
    rule:   DetectionRule,
    result: RuleResult,
    ctx:    DetectionContext,
  ): number {
    if (!rule.minCorroboration || rule.minCorroboration <= 0) return result.score;

    const triggeredCount = ctx.getTriggeredRules().length; // rules already processed before this one
    if (triggeredCount < rule.minCorroboration) {
      return Math.round(result.score * 0.5); // 50% penalty when firing alone
    }
    return result.score;
  }

  // ─── Dependency-ordered evaluation ────────────────────────────────────────
  private resolveOrder(): DetectionRule[] {
    const map      = new Map(this.rules.map(r => [r.id, r]));
    const visited  = new Set<string>();
    const ordered: DetectionRule[] = [];

    const visit = (rule: DetectionRule) => {
      if (visited.has(rule.id)) return;
      visited.add(rule.id);
      for (const depId of (rule.dependsOn ?? [])) {
        const dep = map.get(depId);
        if (dep) visit(dep);
      }
      ordered.push(rule);
    };

    for (const rule of this.rules) visit(rule);
    return ordered;
  }

  /** Expose rule metadata for documentation / UI */
  getRuleManifest(): Array<{
    id: string; description: string; category: string;
    severity: number; weight: number; scoreTarget: string;
  }> {
    return this.rules.map(r => ({
      id:          r.id,
      description: r.description,
      category:    r.category,
      severity:    r.severity,
      weight:      r.weight,
      scoreTarget: r.scoreTarget,
    }));
  }
}
