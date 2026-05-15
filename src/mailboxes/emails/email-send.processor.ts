import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma.service';
import { EncryptionService } from '../../common/encryption/encryption.service';
import { MailboxesService } from '../mailboxes.service';
import { GmailSendProvider } from './providers/gmail-send.provider';
import { OutlookSendProvider } from './providers/outlook-send.provider';
import { SmtpSendProvider } from './providers/smtp-send.provider';
import { AttachmentStorageService } from './attachment-storage.service';
import {
  EMAIL_SEND_QUEUE,
  SendJobData,
} from './email-send.service';
import { EmailProviders } from '@prisma/client';
import { FolderType } from '@prisma/client';
import { google } from 'googleapis';

@Processor(EMAIL_SEND_QUEUE)
@Injectable()
export class EmailSendProcessor extends WorkerHost {
  constructor(
    private prisma: PrismaService,
    private encryption: EncryptionService,
    private mailboxesService: MailboxesService,
    private gmailSendProvider: GmailSendProvider,
    private outlookSendProvider: OutlookSendProvider,
    private smtpSendProvider: SmtpSendProvider,
    private attachmentStorage: AttachmentStorageService,
  ) {
    super();
  }

  async process(
    job: Job<SendJobData, void, string>,
  ): Promise<void> {
    const data = job.data;
    let attachments: Array<{ filename: string; content: Buffer; contentType: string }> = [];

    try {
      if (data.attachments?.length) {
        attachments = await Promise.all(
          data.attachments.map(async (a) => ({
            filename: a.filename,
            content: await this.attachmentStorage.readAttachment(a.url),
            contentType: a.mimeType,
          })),
        );
      }

      const mailbox = await this.prisma.mailBox.findUnique({
        where: { id: data.mailboxId },
        include: { oauthToken: true, imapConfig: true, smtpConfig: true },
      });

      if (!mailbox || mailbox.userId !== data.userId) {
        throw new Error('Mailbox not found');
      }

      const from = mailbox.emailAddress ?? mailbox.displayName;

      const sendOptions = {
        from,
        to: data.to,
        cc: data.cc,
        bcc: data.bcc,
        subject: data.subject,
        bodyText: data.bodyText,
        bodyHtml: data.bodyHtml,
        inReplyTo: data.inReplyTo,
        references: data.references,
        attachments: attachments.length ? attachments : undefined,
      };

      let providerMessageId: string | undefined;

      if (mailbox.provider === EmailProviders.GMAIL && mailbox.oauthToken) {
        const tokens = await this.mailboxesService.getGmailTokens(mailbox.id);
        if (!tokens) throw new Error('Gmail tokens not available');
        const oauth2Client = new google.auth.OAuth2();
        oauth2Client.setCredentials({
          access_token: tokens.accessToken,
          refresh_token: tokens.refreshToken,
        });
        const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
        providerMessageId = await this.gmailSendProvider.send(gmail, sendOptions);
      } else if (
        mailbox.provider === EmailProviders.OUTLOOK &&
        mailbox.oauthToken
      ) {
        const tokens = await this.mailboxesService.getOutlookTokens(mailbox.id);
        if (!tokens) throw new Error('Outlook tokens not available');
        const { Client } = await import('@microsoft/microsoft-graph-client');
        const client = Client.init({
          authProvider: (done) =>
            done(null, tokens.accessToken ?? null),
        });
        await this.outlookSendProvider.send(client, sendOptions);
        // Note: Outlook Graph API /sendMail doesn't return the ID in response.
      } else if (
        mailbox.provider === EmailProviders.CUSTOM &&
        mailbox.imapConfig &&
        mailbox.smtpConfig?.passwordEncrypted
      ) {
        const smtpConfig = {
          host: mailbox.smtpConfig.host,
          port: mailbox.smtpConfig.port,
          secure: mailbox.smtpConfig.secure,
          auth: {
            user: mailbox.emailAddress!,
            pass: this.encryption.decrypt(mailbox.smtpConfig.passwordEncrypted),
          },
        };
        providerMessageId = await this.smtpSendProvider.send(smtpConfig, sendOptions);
      } else {
        throw new Error(
          'Mailbox does not have sending configured. For IMAP/Custom, SMTP must be set up.',
        );
      }

      await this.saveSentEmail(mailbox.id, data, from, providerMessageId);
    } finally {
      // Cleanup is now handled by a separate retention policy/job 
      // to ensure history remains available in the "Sent" folder.
    }
  }

  private async saveSentEmail(
    mailboxId: number,
    data: SendJobData,
    from: string,
    providerMessageId?: string,
  ): Promise<void> {
    let sentFolder = await this.prisma.folder.findFirst({
      where: { mailBoxId: mailboxId, type: FolderType.SENT },
    });
    if (!sentFolder) {
      sentFolder = await this.prisma.folder.create({
        data: {
          mailBoxId: mailboxId,
          name: 'sent',
          type: FolderType.SENT,
          remoteId: 'SENT',
        },
      });
    }

    const messageId = providerMessageId || `<sent-${mailboxId}-${Date.now()}@securemail.local>`;
    await this.prisma.email.create({
      data: {
        mailBoxId: mailboxId,
        folderId: sentFolder.id,
        messageId,
        subject: data.subject,
        fromAddr: from,
        toAddr: [data.to],
        ccAddr: data.cc,
        bccAddr: data.bcc,
        bodyText: data.bodyText,
        bodyHtml: data.bodyHtml,
        isRead: true,
        receivedAt: new Date(),
        attachments: data.attachments?.length
          ? {
              create: data.attachments.map((a) => ({
                filename: a.filename,
                mimeType: a.mimeType,
                size: a.size || 0,
                storagePath: a.url, // Full Cloudinary URL stored as storagePath
              })),
            }
          : undefined,
      },
    });
  }
}
