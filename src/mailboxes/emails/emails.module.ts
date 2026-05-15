import { Module } from '@nestjs/common';
import { BullModule } from '@nestjs/bullmq';
import { EmailsController } from './emails.controller';
import { EmailsService } from './emails.service';
import { EmailSendService, EMAIL_SEND_QUEUE } from './email-send.service';
import { EmailSendProcessor } from './email-send.processor';
import { AttachmentStorageService } from './attachment-storage.service';
import { GmailSendProvider } from './providers/gmail-send.provider';
import { OutlookSendProvider } from './providers/outlook-send.provider';
import { SmtpSendProvider } from './providers/smtp-send.provider';
import { PrismaModule } from '../../prisma.module';
import { AuthModule } from '../../auth/auth.module';
import { MailboxesModule } from '../mailboxes.module';
import { forwardRef } from '@nestjs/common';
import { SecurityModule } from '../../security/security.module';

@Module({
  imports: [
    PrismaModule,
    AuthModule,
    forwardRef(() => MailboxesModule),
    BullModule.registerQueue(
      {
        name: EMAIL_SEND_QUEUE,
        defaultJobOptions: {
          removeOnComplete: 100,
          attempts: 3,
          backoff: { type: 'exponential', delay: 5000 },
        },
      },
      {
        name: 'email-process', // QUEUE_EMAIL_PROCESS from constants
        defaultJobOptions: {
          removeOnComplete: 1000,
          attempts: 3,
          backoff: { type: 'exponential', delay: 2000 },
        },
      }
    ),
    SecurityModule,
  ],
  controllers: [EmailsController],
  providers: [
    EmailsService,
    EmailSendService,
    EmailSendProcessor,
    AttachmentStorageService,
    GmailSendProvider,
    OutlookSendProvider,
    SmtpSendProvider,
  ],
  exports: [EmailsService, EmailSendService, AttachmentStorageService],
})
export class EmailsModule {}
