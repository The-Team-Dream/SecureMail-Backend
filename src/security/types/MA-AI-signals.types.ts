export interface MalwareSignals {
    status?: string;
    message?: string;
    verdict?: string;
    score?: number;
    severity?: string;
    report?: string;
}

/** API / persistence shape (camelCase). Aligns with `AnalysisReport` from gRPC after mapping. */
export interface AiSignals {
    emailId?: string;
    verdict?: string;
    severity?: string;
    confidence?: number;
    summary?: string;
    explanation?: string;
    replySuggestions?: string[];
    isCampaign?: boolean;
    campaignDescription?: string;
    priority?: string;
    priorityReason?: string;
    behavioralAnomaly?: boolean;
    anomalyDescription?: string;
    recommendation?: string;
}

export type AiIntegrationState = 'ok' | 'failed' | 'skipped';

export type AiIntegrationFailureKind =
    | 'deadline'
    | 'unavailable'
    | 'resource_exhausted'
    | 'invalid_argument'
    | 'internal'
    | 'unknown';

export interface AiIntegrationMeta {
    state: AiIntegrationState;
    atMs: number;
    grpcCode?: number;
    message?: string;
    kind?: AiIntegrationFailureKind;
}
