import { DetectionContext } from "src/security/pipeline/7-detection/rule-engine/detection-context";

export interface RuleResult {
    ruleId: string;
    category: RuleCategory;
    scoreTarget: 'phishing' | 'spam' | 'both';
    severity: RuleSeverity;
    triggered: boolean;
    originalScore: number;
    amplifiedScore: number;
    confidence: number;
    explanation: string;
}

export type RuleCategory =
    | 'sender'
    | 'content'
    | 'url'
    | 'headers'
    | 'attachment'
    | 'authentication'
    | 'reputation'
    | 'behavioral'
    | 'advanced';

export type RuleSeverity = 1 | 2 | 3 | 4 | 5;

export interface DetectionRule {
    readonly id: string;
    readonly description: string;
    readonly category: RuleCategory;
    readonly severity: RuleSeverity;
    readonly weight: number;
    readonly scoreTarget: 'phishing' | 'spam' | 'both';
    readonly dependsOn?: string[];
    readonly minCorroboration?: number;
    evaluate(context: Readonly<DetectionContext>): RuleResult | Promise<RuleResult>;
}

export interface RuleNode {
    id: string;
    dependencies: string[];     // rule IDs that must evaluate first
    amplifies: string[];     // rule IDs whose score is amplified when this fires
    amplifyFactor: number;      // multiplier applied to amplified rules
}