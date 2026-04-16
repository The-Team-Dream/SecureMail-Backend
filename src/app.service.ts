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
    const aiUrl = this.config.get('AI_AGENT_GRPC_URL', 'localhost:50051');
    status.ai_agent = await this.checkTcpPort(aiUrl);
    if (status.ai_agent === 'down') status.overall = 'unhealthy';

    // 4. Check Malware Scanner (TCP)
    const malwareUrl = this.config.get('MALWARE_GRPC_URL', 'localhost:50052');
    status.malware_scanner = await this.checkTcpPort(malwareUrl);
    if (status.malware_scanner === 'down') status.overall = 'unhealthy';

    return status;
  }

  private checkTcpPort(url: string): Promise<string> {
    return new Promise((resolve) => {
      const [host, port] = url.split(':');
      const socket = new net.Socket();
      socket.setTimeout(2000);
      socket.once('connect', () => {
        socket.destroy();
        resolve('healthy');
      });
      socket.once('timeout', () => {
        socket.destroy();
        resolve('timeout');
      });
      socket.once('error', () => {
        socket.destroy();
        resolve('down');
      });
      socket.connect(parseInt(port, 10), host);
    });
  }
}
