// ─────────────────────────────────────────────────────────────────────────────
// detection/rules/detection-rule.interface.ts
//
// DetectionRule — the plugin interface every rule must implement.
//
// Architecture principle (from guide):
//   "Instead of if statements, use Plugin Rule System"
//
// Each rule is a self-contained class that:
//   - Declares its own id, description, category, severity, weight
//   - Implements evaluate(context) → RuleResult
//   - Is registered into the RuleRegistry (loaded at startup)
//
// This enables:
//   - Adding new rules without touching the engine
//   - Loading rules from YAML/DSL at runtime
//   - Testing each rule in complete isolation
//   - Generating full rule documentation from metadata
// ─────────────────────────────────────────────────────────────────────────────

import { DetectionContext, RuleResult } from '../rule-engine/detection-context';

// ─── Plugin Rule Interface ─────────────────────────────────────────────────────
export interface DetectionRule {
  /** Unique machine-readable identifier — e.g. 'urgent_phishing_language' */
  readonly id: string;

  /** Human-readable description shown in UI and reports */
  readonly description: string;

  /**
   * Category groups rules for filtering and reporting.
   * Maps directly to RuleCategory in detection-context.ts
   */
  readonly category: 'sender' | 'content' | 'url' | 'headers' | 'attachment' | 'authentication' | 'reputation' | 'behavioral' | 'advanced';

  /**
   * Severity level (1-5 scale):
   *   1 = info, 2 = low, 3 = medium, 4 = high, 5 = critical
   */
  readonly severity: 1 | 2 | 3 | 4 | 5;

  /**
   * Score weight — added to phishingScore or spamScore when triggered.
   * Should be calibrated relative to other rules in the same category.
   */
  readonly weight: number;

  /**
   * Which score bucket this rule contributes to.
   * 'phishing' rules affect phishingScore.
   * 'spam' rules affect spamScore.
   * 'both' adds to both.
   */
  readonly scoreTarget: 'phishing' | 'spam' | 'both';

  /**
   * Optional: rule IDs that must have triggered before this rule runs.
   * Used by the RuleGraph for ordered evaluation.
   */
  readonly dependsOn?: string[];

  /**
   * Optional: minimum number of corroborating rules needed for this rule
   * to be applied at full weight. Set > 0 for rules that are weak alone.
   */
  readonly minCorroboration?: number;

  /**
   * Core evaluation function.
   *
   * Receives the full DetectionContext (read-only).
   * Returns a RuleResult — the engine writes it into the context.
   *
   * Rules MUST be pure (no side effects, no DB calls).
   * Async rules are supported but should be avoided for performance.
   */
  evaluate(context: Readonly<DetectionContext>): RuleResult | Promise<RuleResult>;
}

// ─── Base class (optional convenience) ────────────────────────────────────────
// Rules can extend this to avoid boilerplate. Not required.
export abstract class BaseDetectionRule implements DetectionRule {
  abstract readonly id: string;
  abstract readonly description: string;
  abstract readonly category: DetectionRule['category'];
  abstract readonly severity: DetectionRule['severity'];
  abstract readonly weight: number;
  abstract readonly scoreTarget: DetectionRule['scoreTarget'];
  readonly dependsOn?: string[];
  readonly minCorroboration?: number;

  abstract evaluate(context: Readonly<DetectionContext>): RuleResult | Promise<RuleResult>;

  /** Convenience: build a triggered result */
  protected triggered(explanation: string, scoreOverride?: number): RuleResult {
    return {
      ruleId: this.id,
      category: this.category,
      severity: this.severityLabel(),
      triggered: true,
      score: scoreOverride ?? this.weight,
      confidence: 70,
      explanation,
    };
  }

  /** Convenience: build a not-triggered result */
  protected notTriggered(): RuleResult {
    return {
      ruleId: this.id,
      category: this.category,
      severity: this.severityLabel(),
      triggered: false,
      score: 0,
      confidence: 100,
      explanation: '',
    };
  }

  private severityLabel(): RuleResult['severity'] {
    const map: Record<number, RuleResult['severity']> = {
      1: 'info', 2: 'low', 3: 'medium', 4: 'high', 5: 'critical',
    };
    return map[this.severity] ?? 'medium';
  }
}

// ─── RuleResult type re-export (convenience for rule implementors) ────────────
export type { RuleResult } from '../rule-engine/detection-context';
