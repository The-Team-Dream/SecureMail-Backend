// ─────────────────────────────────────────────────────────────────────────────
// security/security.module.ts  (UPDATED v3)
// ─────────────────────────────────────────────────────────────────────────────

import { Module } from '@nestjs/common';

import { MalwareModule }        from '../malware/malware.module';
import { AiAgentModule }        from '../ai-agent/ai-agent.module';
import { NotificationsModule }  from '../notifications/notifications.module';
import { PrismaModule }         from '../prisma.module';
import { ClassificationModule } from '../classification/classification.module';

import { EmailParserModule }    from './pipeline/email-parser/email-parser.module';
import { AuthenticationModule } from './pipeline/authentication/authentication.module';
import { ReputationModule }     from './pipeline/reputation/reputation.module';
import { UrlAnalysisModule }    from './pipeline/url-analysis/url-analysis.module';
import { UrlSandboxModule }     from './pipeline/url-sandbox/url-sandbox.module';
import { BehaviorModule }       from './pipeline/behavior/behavior.module';
import { ScoringModule }        from './pipeline/scoring/scoring.module';
import { DecisionModule }       from './pipeline/decision/decision.module';
import { MonitoringModule }     from './pipeline/monitoring/monitoring.module';
import { DetectionModule }      from './pipeline/detection/detection.module';
import { IntelligenceModule }   from './intelligence/intelligence.module';

import { SecurityService }      from './security.service';

@Module({
  imports: [
    PrismaModule,
    MalwareModule,
    AiAgentModule,
    NotificationsModule,
    ClassificationModule,
    IntelligenceModule,      // ← NEW: Redis-backed threat intelligence cache
    EmailParserModule,
    AuthenticationModule,
    ReputationModule,        // Updated: now uses IntelligenceModule
    UrlAnalysisModule,       // Updated: now uses IntelligenceModule
    UrlSandboxModule, 
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
    UrlSandboxModule,
    BehaviorModule,
    ScoringModule,
    DecisionModule,
    MonitoringModule,
    DetectionModule,
  ],
})
export class SecurityModule {}
