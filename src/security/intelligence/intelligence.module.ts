// ─────────────────────────────────────────────────────────────────────────────
// security/intelligence/intelligence.module.ts
//
// IntelligenceModule — provides the IntelligenceCacheService.
//
// Redis client is registered here as 'REDIS_CLIENT' provider.
// The module reads REDIS_HOST / REDIS_PORT from ConfigService.
//
// ─── HOW TO MOVE TO EXTERNAL gRPC SERVER ───────────────────────────────────
//   When you're ready to split the intelligence layer to a separate server:
//
//   1. Create a new NestJS microservice project
//   2. Move IntelligenceCacheService there
//   3. Register it as a gRPC server
//   4. Replace the providers[] in this module with a ClientsModule.register()
//      pointing at the new server
//   5. The calling code in ReputationService and UrlAnalysisService stays
//      UNCHANGED because they depend on IntelligenceCacheService interface
// ─────────────────────────────────────────────────────────────────────────────

import { Module }         from '@nestjs/common';
import { ConfigModule, ConfigService }  from '@nestjs/config';
import { IntelligenceCacheService } from './intelligence-cache.service';
import { ThreatFeedsService }       from './threat-feeds.service';

@Module({
  imports: [ConfigModule],
  providers: [
    // ── Redis client factory ──────────────────────────────────────────────────
    // Returns null if REDIS_HOST is not set — IntelligenceCacheService handles
    // the null case gracefully (local-only mode).
    {
      provide: 'REDIS_CLIENT',
      inject:  [ConfigService],
      useFactory: async (config: ConfigService) => {
        const host = config.get<string>('REDIS_HOST');
        if (!host) return null;

        // Lazy-require ioredis so it doesn't break tests that don't have it
        try {
          // eslint-disable-next-line @typescript-eslint/no-require-imports
          const Redis = (await import('ioredis')).default as any;
          const port = parseInt(config.get<string>('REDIS_PORT') ?? '6379', 10);
          const password = config.get<string>('REDIS_PASSWORD');
          return new Redis({
            host,
            port,
            password:      password || undefined,
            lazyConnect:   true,
            enableOfflineQueue: false,
            maxRetriesPerRequest: 1,
            connectTimeout: 3000,
          });
        } catch {
          return null;
        }
      },
    },
    IntelligenceCacheService,
    ThreatFeedsService,
  ],
  exports: [IntelligenceCacheService, ThreatFeedsService],
})
export class IntelligenceModule {}
