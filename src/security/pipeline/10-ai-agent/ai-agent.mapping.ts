import type { AiSignals, AiIntegrationMeta } from 'src/security/types';
import type { AnalysisReportPayload } from './ai-agent.contracts';

export function analysisReportToAiSignals(report: AnalysisReportPayload): AiSignals {
    return {
        emailId: report.email_id,
        verdict: report.verdict,
        severity: report.severity,
        confidence: report.confidence,
        explanation: report.explanation,
        summary: report.summary,
        replySuggestions: report.reply_suggestions,
        isCampaign: report.is_campaign,
        campaignDescription: report.campaign_description,
        priority: report.priority,
        priorityReason: report.priority_reason,
        behavioralAnomaly: report.behavioral_anomaly,
        anomalyDescription: report.anomaly_description,
        recommendation: report.recommendation,
    };
}

export function attachOkIntegrationMeta(
    signals: AiSignals,
    meta: AiIntegrationMeta,
): Record<string, unknown> {
    return { ...signals, __integration: meta };
}

export function failedIntegrationPayload(meta: AiIntegrationMeta): Record<string, unknown> {
    return { __integration: meta };
}
