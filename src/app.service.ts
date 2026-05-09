import { Injectable } from '@nestjs/common';
import { PrismaService } from './prisma.service';
import { ConfigService } from '@nestjs/config';
import Redis from 'ioredis';
import * as net from 'net';

@Injectable()
export class AppService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly config: ConfigService,
  ) {}

  getHello(): string {
    return 'SecureMail API is running';
  }

  async checkHealth() {
    const status: Record<string, any> = {
      overall: 'healthy',
      database: 'unknown',
      redis: 'unknown',
      ai_agent: 'unknown',
      malware_scanner: 'unknown',
    }; 

    // 1. Check Database
    try {
      await this.prisma.$queryRaw`SELECT 1`;
      status.database = 'healthy';
    } catch (err) {
      status.database = 'down';
      status.overall = 'unhealthy';
    }

    // 2. Check Redis
    try {
      const redisHost = this.config.get('REDIS_HOST', 'localhost');
      const redisPort = parseInt(this.config.get('REDIS_PORT', '6379'), 10);
      const redis = new Redis(redisPort, redisHost, {
        maxRetriesPerRequest: 1,
        connectTimeout: 2000,
      });
      await redis.ping();
      status.redis = 'healthy';
      redis.disconnect();
    } catch (err) {
      status.redis = 'down';
      status.overall = 'unhealthy';
    }

    // 3. Check AI Agent (TCP)
    const aiUrl = this.config.get('AI_PORT_URL', this.config.get('AI_PORT', '127.0.0.1:50051'));
    // If AI_PORT is just a number, we might need to handle it. 
    // But for now let's assume it's host:port or just look for AI_AGENT_GRPC_URL first.
    const finalAiUrl = this.config.get('AI_AGENT_GRPC_URL') || (aiUrl.includes(':') ? aiUrl : `127.0.0.1:${aiUrl}`);
    status.ai_agent = await this.checkTcpPort(finalAiUrl);
    if (status.ai_agent !== 'healthy') status.overall = 'unhealthy';

    // 4. Check Malware Scanner (TCP)
    const malwareUrl = this.config.get('MALWARE_PORT_URL', this.config.get('MALWARE_PORT', '127.0.0.1:50052'));
    const finalMalwareUrl = this.config.get('MALWARE_GRPC_URL') || (malwareUrl.includes(':') ? malwareUrl : `127.0.0.1:${malwareUrl}`);
    status.malware_scanner = await this.checkTcpPort(finalMalwareUrl);
    if (status.malware_scanner !== 'healthy') status.overall = 'unhealthy';

    return status;
  }

  private checkTcpPort(url: string): Promise<string> {
    return new Promise((resolve) => {
      const [host, port] = url.split(':');
      const socket = new net.Socket();
      socket.setTimeout(3000); // 3s timeout for stability

      socket.once('connect', () => {
        socket.destroy();
        resolve('healthy');
      });

      socket.once('timeout', () => {
        console.error(`Health Check: Port ${port} on ${host} timed out`);
        socket.destroy();
        resolve('timeout');
      });

      socket.once('error', (err) => {
        console.error(`Health Check: Port ${port} on ${host} failed: ${err.message}`);
        socket.destroy();
        resolve('down');
      });

      socket.connect(parseInt(port, 10), host);
    });
  }
}
