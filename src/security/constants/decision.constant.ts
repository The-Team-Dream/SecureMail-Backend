export const CONFIDENCE_GATES = {
    delete: 85,   // MALICIOUS → بس لو واثقين جداً
    block: 70,   // PHISHING  → محتاج confidence معقولة
    quarantine: 45,   // SPAM/SUSPICIOUS → أي شك → quarantine
} as const;
