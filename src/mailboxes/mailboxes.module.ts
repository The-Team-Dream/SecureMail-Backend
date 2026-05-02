// ─────────────────────────────────────────────────────────────────────────────
// mailboxes/mailboxes.module.ts  (UPDATED v3)
//
// Changes:
//   - ClassificationModule removed from imports (SecurityModule already imports it)
//   - AiAgentModule and MalwareModule removed (SecurityModule already imports them)
//   - SecurityModule import remains — EmailSyncProcessor injects SecurityService
// ─────────────────────────────────────────────────────────────────────────────

import { Module, forwardRef }             from '@nestjs/common';
import { BullModule }         from '@nestjs/bullmq';
import { MailboxesController } from './mailboxes.controller';
import { MailboxesService }   from './mailboxes.service';
import { EmailSyncService }   from './email-sync.service';
import { EmailSyncProcessor } from './email-sync.processor';
import { EmailSyncScheduler } from './email-sync.scheduler';
import { PrismaModule }       from '../prisma.module';
import { AuthModule }         from '../auth/auth.module';
import { NotificationsModule } from '../notifications/notifications.module';
import { AnalyticsModule }    from '../analytics/analytics.module';
import { GmailProvider }      from './providers/gmail.provider';
import { OutlookProvider }    from './providers/outlook.provider';
import { ImapProvider }       from './providers/imap.provider';
import { EMAIL_SYNC_QUEUE }   from './email-sync.service';
import { SecurityModule }     from '../security/security.module';
import { EmailsModule }       from './emails/emails.module';

@Module({
  imports: [
    PrismaModule,
    AuthModule,
    SecurityModule,          // ← provides SecurityService (replaces Classification/AI/Malware)
    NotificationsModule,
    AnalyticsModule,
    forwardRef(() => EmailsModule),
    BullModule.registerQueue({
      name: EMAIL_SYNC_QUEUE,
      defaultJobOptions: {
        removeOnComplete: 100,
        attempts:         3,
        backoff: { type: 'exponential', delay: 5000 },
      },
    }),
  ],
  controllers: [MailboxesController],
  providers: [
    MailboxesService,
    EmailSyncService,
    {
      provide:  EmailSyncProcessor,
      useClass: EmailSyncProcessor,
    },
    EmailSyncScheduler,
    GmailProvider,
    OutlookProvider,
    ImapProvider,
  ],
  exports: [MailboxesService, EmailSyncService],
})
export class MailboxesModule {}
