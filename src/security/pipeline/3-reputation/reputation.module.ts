// ─────────────────────────────────────────────────────────────────────────────
// security/pipeline/reputation/reputation.module.ts  (UPDATED v3)
// ─────────────────────────────────────────────────────────────────────────────

import { Module } from '@nestjs/common';
import { ReputationService } from './reputation.service';
import { IntelligenceModule } from '../../intelligence/intelligence.module';

@Module({
  imports:   [IntelligenceModule],
  providers: [ReputationService],
  exports:   [ReputationService],
})
export class ReputationModule {}
