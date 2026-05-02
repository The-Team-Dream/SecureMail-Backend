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
import { IntelligenceModule }    from './intelligence/intelligence.module';
import { AuthModule }            from 'src/auth/auth.module';
import { PrismaModule }          from 'src/prisma.module';

@Module({
  imports: [
    SecurityModule,
    IntelligenceModule,
    AuthModule,
    PrismaModule,
  ],
  controllers: [SecurityTestController],
})
export class SecurityTestModule {}
