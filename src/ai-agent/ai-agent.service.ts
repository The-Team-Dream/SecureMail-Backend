import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { ClientGrpc } from '@nestjs/microservices';
import { Observable } from 'rxjs';
import { firstValueFrom } from 'rxjs';

export interface EmailAnalysisRequest {
    subject: string;
    from_addr: string;
    body_text: string;
    spam_score: number;
    phishing_score: number;
    has_attachment: boolean;
    malware_verdict: string;
    malware_score: number;
    malware_severity: string;
}

export interface AnalysisReport {
    title: string;
    verdict: string;        // Safe / Suspicious / Malicious
    severity: string;       // Low / Medium / High / Critical
    confidence: number;     // 0.0 - 1.0
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
        subject: string;
        fromAddr: string;
        bodyText: string;
        spamScore: number;
        phishingScore: number;
        hasAttachment: boolean;
        malwareVerdict?: string;
        malwareScore?: number;
        malwareSeverity?: string;
    }): Promise<AnalysisReport | null> {
        try {
            const report = await firstValueFrom(
                this.aiAgentClient.GenerateReport({
                    subject: data.subject ?? '',
                    from_addr: data.fromAddr ?? '',
                    body_text: data.bodyText ?? '',
                    spam_score: data.spamScore ?? 0,
                    phishing_score: data.phishingScore ?? 0,
                    has_attachment: data.hasAttachment ?? false,
                    malware_verdict: data.malwareVerdict ?? '',
                    malware_score: data.malwareScore ?? 0,
                    malware_severity: data.malwareSeverity ?? '',
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
