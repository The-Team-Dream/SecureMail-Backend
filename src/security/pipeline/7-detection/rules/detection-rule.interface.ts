import { DetectionRule, RuleResult } from 'src/security/types';
import { DetectionContext } from '../rule-engine/detection-context';

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

  protected triggered(explanation: string, scoreOverride?: number, confidence: number = 70): RuleResult {
    return {
      ruleId:         this.id,
      category:       this.category,
      severity:       this.severity,
      triggered:      true,
      originalScore:  scoreOverride ?? this.weight,
      amplifiedScore: scoreOverride ?? this.weight, // بيتحدث بعدين من RuleGraphService
      scoreTarget:this.scoreTarget,
      confidence,
      explanation,
    };
  }

  protected notTriggered(): RuleResult {
    return {
      ruleId:         this.id,
      category:       this.category,
      severity:       this.severity,
      triggered:      false,
      originalScore:  0,
      amplifiedScore: 0,
      confidence:     100,
      scoreTarget:this.scoreTarget,
      explanation:    '',
    };
  }
}