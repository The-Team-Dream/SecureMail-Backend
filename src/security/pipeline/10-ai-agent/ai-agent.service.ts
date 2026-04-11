import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import type { ClientGrpc } from '@nestjs/microservices';
import { Observable, timeout } from 'rxjs';
import { firstValueFrom } from 'rxjs';
import { status } from '@grpc/grpc-js';

import type { EmailAnalysisRequestPayload, AnalysisReportPayload, RuleHit } from './ai-agent.contracts';
import type { AiAgentGenerateInput, AiAgentGenerateOutcome, AiAgentFailureKind } from './ai-agent.types';

export type { RuleHit, AnalysisReportPayload, EmailAnalysisRequestPayload } from './ai-agent.contracts';

interface AIAgentGrpcService {
    GenerateReport(request: EmailAnalysisRequestPayload): Observable<AnalysisReportPayload>;
}

const RETRYABLE = new Set<number>([status.UNAVAILABLE]);

function classifyGrpcFailure(err: unknown): {
    grpcCode?: number;
    message: string;
    kind: AiAgentFailureKind;
} {
    const e = err as { code?: number; details?: string; message?: string };
    const grpcCode = typeof e?.code === 'number' ? e.code : undefined;
    const message = (e?.details || e?.message || String(err)).slice(0, 2000);
    if (grpcCode === status.DEADLINE_EXCEEDED) {
        return { grpcCode, message, kind: 'deadline' };
    }
    if (grpcCode === status.UNAVAILABLE) {
        return { grpcCode, message, kind: 'unavailable' };
    }
    if (grpcCode === status.RESOURCE_EXHAUSTED) {
        return { grpcCode, message, kind: 'resource_exhausted' };
    }
    if (grpcCode === status.INVALID_ARGUMENT) {
        return { grpcCode, message, kind: 'invalid_argument' };
    }
    if (grpcCode === status.INTERNAL || grpcCode === status.UNKNOWN) {
        return { grpcCode, message, kind: 'internal' };
    }
    return { grpcCode, message, kind: 'unknown' };
}

@Injectable()
export class AiAgentService implements OnModuleInit {
    private readonly logger = new Logger(AiAgentService.name);
    private aiAgentClient!: AIAgentGrpcService;

    constructor(
        @Inject('AI_AGENT_SERVICE') private readonly client: ClientGrpc,
    ) {}

    onModuleInit(): void {
        this.aiAgentClient = this.client.getService<AIAgentGrpcService>('AIAgentService');
    }

    /**
     * Transport + contract boundary: never throws; returns discriminated outcome for the pipeline.
     */
    async generateReport(data: AiAgentGenerateInput): Promise<AiAgentGenerateOutcome> {
        const maxBody = Math.max(
            4096,
            Number(process.env.AI_AGENT_MAX_BODY_CHARS ?? 120_000) || 120_000,
        );
        const bodyText = this.truncateUtf8(data.bodyText ?? '', maxBody);

        const request: EmailAnalysisRequestPayload = {
            email_id: data.emailId ?? '',
            subject: data.subject ?? '',
            from_addr: data.fromAddr ?? '',
            from_name: data.fromName ?? '',
            body_text: bodyText,
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
        };

        const deadlineMs = Math.max(
            1000,
            Number(process.env.AI_AGENT_GRPC_MS ?? 60_000) || 60_000,
        );
        const maxRetries = Math.min(
            4,
            Math.max(0, Number(process.env.AI_AGENT_GRPC_RETRIES ?? 2) || 2),
        );

        let lastErr: unknown;
        for (let attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                const report = await firstValueFrom(
                    this.aiAgentClient.GenerateReport(request).pipe(timeout({ first: deadlineMs })),
                );
                this.logger.log(`AI Agent report ok for email_id=${request.email_id}`);
                return { ok: true, report };
            } catch (err) {
                lastErr = err;
                const code = (err as { code?: number })?.code;
                if (attempt < maxRetries && code !== undefined && RETRYABLE.has(code)) {
                    const ms = Math.min(2000, 150 * 2 ** attempt);
                    this.logger.warn(`AI Agent gRPC retry #${attempt + 1} after code=${code}, delay=${ms}ms`);
                    await new Promise<void>(resolve => setTimeout(resolve, ms));
                    continue;
                }
                const f = classifyGrpcFailure(err);
                this.logger.warn(
                    `AI Agent gRPC failed kind=${f.kind} code=${f.grpcCode ?? 'n/a'}: ${f.message}`,
                );
                return { ok: false, error: f };
            }
        }
        const f = classifyGrpcFailure(lastErr);
        return { ok: false, error: f };
    }

    private truncateUtf8(text: string, maxChars: number): string {
        if (text.length <= maxChars) {
            return text;
        }
        this.logger.warn(`AI request body truncated from ${text.length} to ${maxChars} chars`);
        return text.slice(0, maxChars);
    }
}
