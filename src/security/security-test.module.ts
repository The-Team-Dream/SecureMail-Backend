// ─────────────────────────────────────────────────────────────────────────────
// security/security-test.module.ts
//
// SecurityTestModule — development/testing module.
//
// ⚠️  Import into app.module.ts ONLY in non-production environments:
//
//   // app.module.ts
//   imports: [
//     ...
//     ...(process.env.NODE_ENV !== 'production' ? [SecurityTestModule] : []),
//   ],
// ─────────────────────────────────────────────────────────────────────────────

import { Module }                from '@nestjs/common';
import { SecurityModule }        from './security.module';
import { SecurityTestController } from './security-test.controller';
import { UrlSandboxModule } from './pipeline/url-sandbox/url-sandbox.module';
import { IntelligenceModule }    from './intelligence/intelligence.module';

@Module({
  imports: [
    SecurityModule,
    IntelligenceModule,
    UrlSandboxModule,
  ],
  controllers: [SecurityTestController],
})
export class SecurityTestModule {}
