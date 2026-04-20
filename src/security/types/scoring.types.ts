export type RiskTier = 'SAFE' | 'SPAM' | 'SUSPICIOUS' | 'PHISHING' | 'MALICIOUS';

export interface ScoreBreakdown {
    // Tier 1 — Hard Signals
    authPenalty: number;   // SPF + DKIM + DMARC failures
    reputationScore: number;   // IP + Domain threat feeds

    // Tier 2 — Soft Signals
    ruleScore: number;   // Rule Engine (× RULE_MATURITY_FACTOR)
    behaviorScore: number;   // Per-user behavioral anomaly

    // Tier 3 — Amplifiers
    correlationBonus: number;   // Attack pattern bonus
    urlThreatScore: number;   // URL threat score
    urlDomainAmplifier: number;   // URL + Domain spoof combined amplifier
    becReplyToBonus: number;   // BEC behavioral + reply-to mismatch
    malwareScore: number;

    // Totals
    rawTotal: number;
    finalScore: number;
}

export interface RiskAssessment {
    spamScore: number;
    phishingScore: number;
    finalScore: number;
    breakdown: ScoreBreakdown;
    isSpam: boolean;
    isPhishing: boolean;
    isMalware: boolean;
    riskTier: RiskTier;
    tier: RiskTier;
    riskLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
    confidence: number;
}
