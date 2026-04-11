import { existsSync, readFileSync } from 'fs';
import { credentials as grpcCredentials, type ChannelCredentials } from '@grpc/grpc-js';

export function createAiAgentChannelCredentials(): ChannelCredentials {
    if (process.env.AI_AGENT_GRPC_USE_TLS === 'true') {
        const rootCa = process.env.AI_AGENT_GRPC_ROOT_CERT;
        if (rootCa && existsSync(rootCa)) {
            return grpcCredentials.createSsl(readFileSync(rootCa));
        }
        return grpcCredentials.createSsl();
    }
    return grpcCredentials.createInsecure();
}
