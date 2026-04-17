import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { DetectionContext } from '../rule-engine/detection-context';

import * as allRules from './'
import { DetectionRule, RuleCategory, RuleResult } from 'src/security/types';

@Injectable()
export class RuleRegistry implements OnModuleInit {
  private readonly logger = new Logger(RuleRegistry.name);
  private readonly rules: DetectionRule[] = [];

  onModuleInit(): void {
    this.registerBuiltins();
    this.logger.log(
      `RuleRegistry initialized: ${this.rules.length} rules loaded ` +
      `[${[...new Set(this.rules.map(r => r.category))].join(', ')}]`,
    );
  }

  private registerBuiltins(): void {
    this.register(new allRules.SenderDisplayNameMismatchRule());
    this.register(new allRules.DisplayNameImpersonationRule());
    this.register(new allRules.DisposableDomainRule());
    this.register(new allRules.ReplyToDomainMismatchRule());
    this.register(new allRules.FirstContactRiskRule());
    this.register(new allRules.SuspiciousIpRule());
    this.register(new allRules.AuthFailureRule());
    this.register(new allRules.IpBasedUrlRule());
    this.register(new allRules.ShortenedUrlRule());
    this.register(new allRules.MaliciousUrlRule());
    this.register(new allRules.UrgentPhishingLanguageRule());
    this.register(new allRules.BECLanguageRule());
    this.register(new allRules.CredentialHarvestingRule());
    this.register(new allRules.ExcessiveCapitalizationRule());
    this.register(new allRules.ExcessiveExclamationRule());
    this.register(new allRules.RiskyAttachmentRule());
    this.register(new allRules.ConversationHijackingRule());
    this.register(new allRules.HomoglyphDomainSpoofingRule());
    this.register(new allRules.LookalikeDomainRule());
    this.register(new allRules.BrandAbuseRule());
    this.register(new allRules.HTMLObfuscationRule());
    this.register(new allRules.Base64EncodedUrlRule());
    this.register(new allRules.NewlyRegisteredDomainRule());
  }

  register(rule: DetectionRule): void {
    if (this.rules.find(r => r.id === rule.id)) {
      this.logger.warn(`RuleRegistry: duplicate rule id "${rule.id}" — skipping`);
      return;
    }
    this.rules.push(rule);
  }
  
  getAll(): DetectionRule[] {
    return this.rules;
  }

  getByCategory(category: RuleCategory): DetectionRule[] {
    return this.rules.filter(r => r.category === category);
  }

  async evaluateAll(ctx: DetectionContext): Promise<void> {
    const allRules = this.resolveOrder();
    let somethingTriggered: boolean;
    do {
      somethingTriggered = false;
      for (const rule of allRules) {
        if (ctx.ruleResults.has(rule.id)) continue;
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
        if (!result.triggered) continue;
        ctx.addResult(result);
        somethingTriggered = true;
      }
    } while (somethingTriggered);
  }

  // ─── Corroboration penalty ─────────────────────────────────────────────────
  // Rules with minCorroboration > 0 are weakened if they fire alone.
  // Once 2+ rules fire together, they apply at full weight.
  private applyCorroborationPenalty(
    rule: DetectionRule,
    result: RuleResult,
    ctx: DetectionContext,
  ): number {
    if (!rule.minCorroboration || rule.minCorroboration <= 0) return result.originalScore;

    const triggeredCount = ctx.getTriggeredRules().length; // rules already processed before this one
    if (triggeredCount < rule.minCorroboration) {
      return Math.round(result.originalScore * 0.5); // 50% penalty when firing alone
    }
    return result.originalScore;
  }

  // ─── Dependency-ordered evaluation ────────────────────────────────────────
  private resolveOrder(): DetectionRule[] {
    const map = new Map(this.rules.map(r => [r.id, r]));
    const visited = new Set<string>();
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
      id: r.id,
      description: r.description,
      category: r.category,
      severity: r.severity,
      weight: r.weight,
      scoreTarget: r.scoreTarget,
    }));
  }
}
