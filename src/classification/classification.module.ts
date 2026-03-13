import { Module }       from '@nestjs/common';
import { JwtModule }    from '@nestjs/jwt';
import { PrismaService } from '../prisma.service';
import { AuthModule }    from '../auth/auth.module';

import { ClassificationController } from './classification.controller';
import { ClassificationService }    from './classification.service';
import { DomainRules }              from './rules/domain.rules';
import { LinkRules }                from './rules/link.rules';
import { ContentRules }             from './rules/content.rules';
import { SenderRules }              from './rules/sender.rules';
import { HeaderRules }              from './rules/header.rules';
// InfrastructureRules — removed intentionally (STUB rules 27+28 not active yet)
// Rule 27 (newly_registered_domain) و Rule 28 (malicious_url_reputation)
// محتاجين external APIs — هيتضافوا لما الـ WHOIS/VirusTotal integration يكتمل

@Module({
  imports: [AuthModule],
  controllers: [ClassificationController],
  providers: [
    PrismaService,
    ClassificationService,
    DomainRules,
    LinkRules,
    ContentRules,
    SenderRules,
    HeaderRules,
    // InfrastructureRules — uncomment when WHOIS + VirusTotal APIs are integrated
  ],
  exports: [ClassificationService],
})
export class ClassificationModule {}
