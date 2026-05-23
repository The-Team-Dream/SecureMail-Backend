import { Inject, Injectable, Logger, OnModuleInit } from '@nestjs/common';
import type { ClientGrpc } from '@nestjs/microservices';
import { Observable, timeout, TimeoutError } from 'rxjs';
import { firstValueFrom } from 'rxjs';
import { status } from '@grpc/grpc-js';

import type { EmailAnalysisRequestPayload, AnalysisReportPayload, RuleHit } from './ai-agent.contracts';
import type { AiAgentGenerateInput, AiAgentGenerateOutcome, AiAgentFailureKind } from './ai-agent.types';

export type { RuleHit, AnalysisReportPayload, EmailAnalysisRequestPayload } from './ai-agent.contracts';

interface AIAgentGrpcService {
    GenerateReport(request: EmailAnalysisRequestPayload): Observable<AnalysisReportPayload>;
}

// UNAVAILABLE → transient network issue, retry quickly
// RESOURCE_EXHAUSTED → quota/rate limit (429), retry after a longer back-off
const RETRYABLE = new Set<number>([status.UNAVAILABLE, status.RESOURCE_EXHAUSTED]);

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
        this.logger.log('✅ AI Agent gRPC Service initialized and ready.');
    }

    /**
     * Transport + contract boundary: never throws; returns discriminated outcome for the pipeline.
     */
    async generateReport(data: AiAgentGenerateInput): Promise<AiAgentGenerateOutcome> {
        // ── Smart body extraction ────────────────────────────────────────────────
        // The AI doesn't need the full email body for security analysis.
        // The backend rule engine already handles heavy signal extraction.
        // We only send the most security-relevant segments to stay within quota:
        //   • Opening (first 2,500 chars) — reveals sender intent & social engineering
        //   • Closing (last 500 chars)    — reveals call-to-action & suspicious links
        // This reduces token usage from ~30,000 → ~800 per large email.
        const bodyText = this.extractSecurityRelevantBody(data.bodyText ?? '');

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
            Number(process.env.AI_AGENT_GRPC_MS ?? 300_000) || 300_000,
        );
        const maxRetries = Math.min(
            4,
            Math.max(0, Number(process.env.AI_AGENT_GRPC_RETRIES ?? 2) || 2),
        );

        this.logger.log(
            `Calling AI Agent gRPC for email_id=${request.email_id}. Timeout limit: ${deadlineMs}ms, Max retries: ${maxRetries}`,
        );

        let lastErr: unknown;
        for (let attempt = 0; attempt <= maxRetries; attempt++) {
            try {
                if (attempt > 0) {
                    this.logger.log(`AI Agent gRPC attempt #${attempt + 1}/${maxRetries + 1} for email_id=${request.email_id}...`);
                }
                const report = await firstValueFrom(
                    this.aiAgentClient.GenerateReport(request).pipe(timeout({ first: deadlineMs })),
                );
                this.logger.log(`AI Agent report ok for email_id=${request.email_id}`);
                return { ok: true, report };
            } catch (err) {
                lastErr = err;
                const isTimeout =
                    err instanceof TimeoutError ||
                    (err instanceof Error &&
                        (err.name === 'TimeoutError' || err.message === 'Timeout has occurred'));

                const code = (err as { code?: number })?.code;
                const isRetryable = isTimeout || (code !== undefined && RETRYABLE.has(code));

                if (attempt < maxRetries && isRetryable) {
                    const isQuota = code === status.RESOURCE_EXHAUSTED;
                    const baseMs = isQuota ? 3_000 : (isTimeout ? 1_500 : 150);
                    const capMs = isQuota ? 15_000 : (isTimeout ? 5_000 : 2_000);
                    const ms = Math.min(capMs, baseMs * 2 ** attempt);

                    const reasonStr = isTimeout ? 'timeout' : isQuota ? 'quota exhausted' : 'unavailable';
                    this.logger.warn(
                        `AI Agent gRPC retry #${attempt + 1} after ${reasonStr} (code=${code ?? 'n/a'}), delay=${ms}ms`,
                    );
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

    /**
     * Extracts the most security-relevant portions of an email body to minimize
     * token usage while retaining maximum signal for threat detection.
     *
     * Strategy:
     *   - Opening (first 2,500 chars): Contains sender intent, social engineering cues,
     *     urgency language, and impersonation attempts.
     *   - Closing (last 500 chars): Contains call-to-action, suspicious links,
     *     and credential-harvesting instructions.
     *   - Middle content is omitted (typically boilerplate, HTML padding, legal text).
     *
     * Token budget: ~800 tokens vs. up to 30,000 for full bodies (120k chars).
     */
    private extractSecurityRelevantBody(text: string): string {
        const HEAD_CHARS = 2_500;
        const TAIL_CHARS = 500;
        const SEPARATOR = '\n[...middle content omitted for quota efficiency...]\n';

        if (text.length <= HEAD_CHARS + TAIL_CHARS) {
            return text; // Short email — send in full
        }

        const head = text.slice(0, HEAD_CHARS);
        const tail = text.slice(-TAIL_CHARS);

        this.logger.debug(
            `Body extraction: ${text.length} chars → ${HEAD_CHARS + TAIL_CHARS} chars ` +
            `(~${Math.round((HEAD_CHARS + TAIL_CHARS) / 4)} tokens saved: ~${Math.round((text.length - HEAD_CHARS - TAIL_CHARS) / 4)})`,
        );

        return `${head}${SEPARATOR}${tail}`;
    }
}
