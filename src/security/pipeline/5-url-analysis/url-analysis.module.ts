// ─────────────────────────────────────────────────────────────────────────────
// security/pipeline/url-analysis/url-analysis.module.ts  (UPDATED v3)
// ─────────────────────────────────────────────────────────────────────────────

import { Module } from '@nestjs/common';
import { UrlAnalysisService } from './url-analysis.service';
import { IntelligenceModule } from '../../intelligence/intelligence.module';

@Module({
  imports:   [IntelligenceModule],
  providers: [UrlAnalysisService],
  exports:   [UrlAnalysisService],
})
export class UrlAnalysisModule {}
