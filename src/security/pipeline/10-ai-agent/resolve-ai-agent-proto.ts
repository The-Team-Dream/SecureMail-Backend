import { existsSync } from 'fs';
import { join } from 'path';

/**
 * Single source of truth: repo-root `contracts/ai-agent.proto`.
 * Expects process.cwd() to be SecureMail-Backend, or cwd at monorepo root.
 */
export function resolveAiAgentProtoPath(): string {
    const cwd = process.cwd();
    const candidates = [
        join(cwd, 'contracts', 'ai-agent.proto'),
        join(cwd, '..', 'contracts', 'ai-agent.proto'),
    ];
    for (const p of candidates) {
        if (existsSync(p)) {
            return p;
        }
    }
    throw new Error(
        `contracts/ai-agent.proto not found. Tried:\n${candidates.join('\n')}\n` +
            'Ensure the monorepo includes /contracts/ai-agent.proto and start Nest from SecureMail-Backend.',
    );
}
