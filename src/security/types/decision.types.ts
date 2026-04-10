export type VerdictLabel = 'SAFE' | 'SPAM' | 'SUSPICIOUS' | 'PHISHING' | 'MALICIOUS';

export interface FinalVerdict {
    label: VerdictLabel;
    riskScore: number;
    confidence: number;
    action: 'allow' | 'quarantine' | 'block' | 'delete';
    explanation: string;
    details: string[];
    triggeredRules: string[];
    attackPatterns: string[];
    recommendations: string[];
}
