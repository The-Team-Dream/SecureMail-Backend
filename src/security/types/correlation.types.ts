export interface AttackPattern {
    id: string;
    name: string;
    description: string;
    requiredRules: string[];
    optionalRules?: string[];
    bonusScore: number;
    severity: 'critical' | 'high' | 'medium';
}
export interface CorrelationResult {
    patterns: string[];     // attack pattern names detected
    bonusScore: number;       // extra score added by correlation
    description: string;
}
