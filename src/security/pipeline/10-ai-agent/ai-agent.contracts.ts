/** Field names match `contracts/ai-agent.proto` (snake_case on wire; keepCase in Nest loader). */

export interface RuleHit {
    rule: string;
    score: number;
    description: string;
}

export interface EmailAnalysisRequestPayload {
    email_id: string;
    subject: string;
    from_addr: string;
    from_name: string;
    body_text: string;
    spam_score: number;
    phishing_score: number;
    is_spam: boolean;
    is_phishing: boolean;
    rule_hits: RuleHit[];
    has_attachment: boolean;
    malware_verdict: string;
    malware_score: number;
    malware_severity: string;
    mailbox_id: number;
    previous_email_count: number;
    sender_typical_topic: string;
}

export interface AnalysisReportPayload {
    email_id: string;
    verdict: string;
    severity: string;
    confidence: number;
    explanation: string;
    summary: string;
    reply_suggestions: string[];
    is_campaign: boolean;
    campaign_description: string;
    priority: string;
    priority_reason: string;
    behavioral_anomaly: boolean;
    anomaly_description: string;
    recommendation: string;
}
