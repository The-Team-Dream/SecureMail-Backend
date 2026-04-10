// ─────────────────────────────────────────────────────────────────────────────
// security/security.module.ts  (UPDATED v3)
// ─────────────────────────────────────────────────────────────────────────────

import { Module } from '@nestjs/common';

import { MalwareModule }        from './pipeline/6-malware/malware.module';
import { AiAgentModule }        from './pipeline/10-ai-agent/ai-agent.module';
import { NotificationsModule }  from '../notifications/notifications.module';
import { PrismaModule }         from '../prisma.module';

import { EmailParserModule }    from './pipeline/1-email-parser/email-parser.module';
import { AuthenticationModule } from './pipeline/2-authentication/authentication.module';
import { ReputationModule }     from './pipeline/3-reputation/reputation.module';
import { UrlAnalysisModule }    from './pipeline/5-url-analysis/url-analysis.module';
import { BehaviorModule }       from './pipeline/4-behavior/behavior.module';
import { ScoringModule }        from './pipeline/8-scoring/scoring.module';
import { DecisionModule }       from './pipeline/9-decision/decision.module';
import { MonitoringModule }     from './pipeline/monitoring/monitoring.module';
import { DetectionModule }      from './pipeline/7-detection/detection.module';
import { IntelligenceModule }   from './intelligence/intelligence.module';

import { SecurityService }      from './security.service';

@Module({
  imports: [
    PrismaModule,
    MalwareModule,
    AiAgentModule,
    NotificationsModule,
    IntelligenceModule,      // ← NEW: Redis-backed threat intelligence cache
    EmailParserModule,
    AuthenticationModule,
    ReputationModule,        // Updated: now uses IntelligenceModule
    UrlAnalysisModule,       // Updated: now uses IntelligenceModule
    BehaviorModule,
    ScoringModule,
    DecisionModule,
    MonitoringModule,
    DetectionModule,
  ],
  providers: [SecurityService],
  exports: [
    SecurityService,
    IntelligenceModule,
    EmailParserModule,
    AuthenticationModule,
    ReputationModule,
    UrlAnalysisModule,
    BehaviorModule,
    ScoringModule,
    DecisionModule,
    MonitoringModule,
    DetectionModule,
  ],
})
export class SecurityModule {}
