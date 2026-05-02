import { Module } from '@nestjs/common';
import { RetentionService } from './retention.service';
import { PrismaModule } from '../prisma.module';
import { EmailsModule } from '../mailboxes/emails/emails.module';

@Module({
  imports: [PrismaModule, EmailsModule],
  providers: [RetentionService],
})
export class RetentionModule {}
