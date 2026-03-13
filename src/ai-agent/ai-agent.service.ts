import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import type { ClientGrpc } from '@nestjs/microservices';
import { Observable } from 'rxjs';
import { firstValueFrom } from 'rxjs';

export interface RuleHit {
    rule: string;
    score: number;
    description: string;
}

export interface EmailAnalysisRequest {
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

export interface AnalysisReport {
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

interface AIAgentGrpcService {
    GenerateReport(request: EmailAnalysisRequest): Observable<AnalysisReport>;
}

@Injectable()
export class AiAgentService implements OnModuleInit {
    private readonly logger = new Logger(AiAgentService.name);
    private aiAgentClient: AIAgentGrpcService;

    constructor(
        @Inject('AI_AGENT_SERVICE') private readonly client: ClientGrpc,
    ) { }

    onModuleInit() {
        this.aiAgentClient =
            this.client.getService<AIAgentGrpcService>('AIAgentService');
    }

    async generateReport(data: {
        emailId: string;
        subject: string;
        fromAddr: string;
        fromName: string;
        bodyText: string;

        spamScore: number;
        phishingScore: number;
        isSpam: boolean;
        isPhishing: boolean;
        ruleHits: any[];

        hasAttachment: boolean;
        malwareVerdict?: string;
        malwareScore?: number;
        malwareSeverity?: string;

        mailboxId: number;
        previousEmailCount: number;
        senderTypicalTopic: string;
    }): Promise<AnalysisReport | null> {
        try {
            const report = await firstValueFrom(
                this.aiAgentClient.GenerateReport({
                    email_id: data.emailId ?? '',
                    subject: data.subject ?? '',
                    from_addr: data.fromAddr ?? '',
                    from_name: data.fromName ?? '',
                    body_text: data.bodyText ?? '',

                    spam_score: data.spamScore ?? 0,
                    phishing_score: data.phishingScore ?? 0,
                    is_spam: data.isSpam ?? false,
                    is_phishing: data.isPhishing ?? false,

                    rule_hits: data.ruleHits ?? [],

                    has_attachment: data.hasAttachment ?? false,
                    malware_verdict: data.malwareVerdict ?? '',
                    malware_score: data.malwareScore ?? 0,
                    malware_severity: data.malwareSeverity ?? '',

                    mailbox_id: data.mailboxId ?? 0,
                    previous_email_count: data.previousEmailCount ?? 0,
                    sender_typical_topic: data.senderTypicalTopic ?? '',
                }),
            );
            return report;
        } catch (err) {
            // Non-fatal: AI Agent might be unavailable
            this.logger.warn(
                `AI Agent gRPC call failed (non-fatal): ${err instanceof Error ? err.message : String(err)}`,
            );
            return null;
        }
    }
}
