import type { AnalysisReportPayload, RuleHit } from './ai-agent.contracts';

export type AiAgentFailureKind =
    | 'deadline'
    | 'unavailable'
    | 'resource_exhausted'
    | 'invalid_argument'
    | 'internal'
    | 'unknown';

export interface AiAgentGenerateError {
    message: string;
    grpcCode?: number;
    kind: AiAgentFailureKind;
}

export type AiAgentGenerateOutcome =
    | { ok: true; report: AnalysisReportPayload }
    | { ok: false; error: AiAgentGenerateError };

export interface AiAgentGenerateInput {
    emailId: string;
    subject: string;
    fromAddr: string;
    fromName: string;
    bodyText: string;
    spamScore: number;
    phishingScore: number;
    isSpam: boolean;
    isPhishing: boolean;
    ruleHits: RuleHit[];
    hasAttachment: boolean;
    malwareVerdict?: string;
    malwareScore?: number;
    malwareSeverity?: string;
    mailboxId: number;
    previousEmailCount: number;
    senderTypicalTopic: string;
}
