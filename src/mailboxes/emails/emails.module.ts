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
import { ClassificationModule } from '../../classification/classification.module';
import { MailboxesModule } from '../mailboxes.module';

@Module({
  imports: [
    PrismaModule,
    AuthModule,
    ClassificationModule,
    MailboxesModule,
    BullModule.registerQueue({
      name: EMAIL_SEND_QUEUE,
      defaultJobOptions: {
        removeOnComplete: 100,
        attempts: 3,
        backoff: { type: 'exponential', delay: 5000 },
      },
    }),
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
  exports: [EmailsService, EmailSendService],
})
export class EmailsModule {}
