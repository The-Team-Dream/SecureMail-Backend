import { Module } from '@nestjs/common';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { join } from 'path';
import { AiAgentService } from './ai-agent.service';

@Module({
  imports: [
    ClientsModule.register([
      {
        name: 'AI_AGENT_SERVICE',
        transport: Transport.GRPC,
        options: {
          package: 'aiagent',
          protoPath: join(process.cwd(), 'src/proto/ai-agent.proto'),
          url: process.env.AI_AGENT_GRPC_URL ?? 'localhost:50051',
        },
      },
    ]),
  ],
  providers: [AiAgentService],
  exports: [AiAgentService],
})
export class AiAgentModule {}
