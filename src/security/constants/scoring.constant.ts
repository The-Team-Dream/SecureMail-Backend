export const RISK_THRESHOLDS = {
    MALICIOUS: 90,
    PHISHING: 75,
    SUSPICIOUS: 50,
    SPAM: 25,
    SAFE: 0,
} as const;

export const CAP = {
    rule: 100,
    reputation: 40,
    malware: 80,
    behavior: 25,
    correlation: 50,
    url: 30,
} as const;

export const TOTAL_MAX = CAP.rule + CAP.reputation + CAP.malware + CAP.behavior + CAP.correlation + CAP.url;

export const TIER_CAPS = {
    // Tier 1 — Hard Signals (high trust)
    auth: 50,   // SPF + DKIM + DMARC failures
    reputation: 40,   // IP + Domain threat feeds

    // Tier 2 — Soft Signals (medium trust)
    rules: 60,   // Rule Engine — immature حالياً، cap منخفض
    behavior: 25,   // Per-user behavioral anomaly

    // Tier 3 — Amplifiers (context boosters)
    correlation: 35,  // Attack pattern bonus
    url: 30,  // URL threat score

    // Amplifier bonuses
    urlDomainAmplifier: 20,
    becReplyToBonus: 30,
} as const;

export const RULE_MATURITY_FACTOR = 0.7;

export const AMPLIFIER_BASE_THRESHOLD = 20;