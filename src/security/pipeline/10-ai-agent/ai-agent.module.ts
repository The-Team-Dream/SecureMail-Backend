import { Module } from '@nestjs/common';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { AiAgentService } from './ai-agent.service';
import { createAiAgentChannelCredentials } from './ai-agent.grpc-options';
import { resolveAiAgentProtoPath } from './resolve-ai-agent-proto';

const sendMb = Number(process.env.AI_AGENT_GRPC_MAX_SEND_MB);
const recvMb = Number(process.env.AI_AGENT_GRPC_MAX_RECV_MB);
const maxSend = (Number.isFinite(sendMb) ? sendMb : 8) * 1024 * 1024;
const maxRecv = (Number.isFinite(recvMb) ? recvMb : 8) * 1024 * 1024;

@Module({
  imports: [
    ClientsModule.register([
      {
        name: 'AI_AGENT_SERVICE',
        transport: Transport.GRPC,
        options: {
          package: 'aiagent',
          protoPath: resolveAiAgentProtoPath(),
          url: process.env.AI_AGENT_GRPC_URL ?? '127.0.0.1:50051',
          credentials: createAiAgentChannelCredentials(),
          loader: {
            keepCase: true,
            longs: String,
            enums: String,
            defaults: false,
            oneofs: true,
          },
          channelOptions: {
            'grpc.max_send_message_length': maxSend,
            'grpc.max_receive_message_length': maxRecv,
          },
        },
      },
    ]),
  ],
  providers: [AiAgentService],
  exports: [AiAgentService],
})
export class AiAgentModule {}
