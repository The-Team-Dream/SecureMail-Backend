import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { NotificationsService } from '../notifications/notifications.service';
import { SecurityService, SecurityPipelineInput } from '../security/security.service';
import { GmailProvider } from './providers/gmail.provider';
import { OutlookProvider } from './providers/outlook.provider';
import { MailboxesService } from './mailboxes.service';
import { AttachmentStorageService } from './emails/attachment-storage.service';
import { QUEUE_EMAIL_PROCESS } from '../common/constants/queues';
import { EmailProviders, FolderType, NotificationType, AnalysisStatus } from '@prisma/client';
import { google } from 'googleapis';

export interface ProcessEmailJobData {
  emailId: number;
  mailBoxId: number;
  userId: number;
  messageId: string;
  gmailAttachmentParts?: Array<{ filename: string; mimeType: string; attachmentId: string }>;
  outlookHasAttachments?: boolean;
  existingAttachmentIds?: number[];
}

@Processor(QUEUE_EMAIL_PROCESS, { concurrency: 3 })
@Injectable()
export class EmailProcessProcessor extends WorkerHost {
  private readonly logger = new Logger(EmailProcessProcessor.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly securityService: SecurityService,
    private readonly notificationsService: NotificationsService,
    private readonly gmailProvider: GmailProvider,
    private readonly outlookProvider: OutlookProvider,
    private readonly mailboxesService: MailboxesService,
    private readonly attachmentStorage: AttachmentStorageService,
  ) {
    super();
    this.logger.log('EmailProcessProcessor initialized and waiting for jobs...');
  }

  async process(job: Job<ProcessEmailJobData, void, string>): Promise<void> {
    const data = job.data;
    this.logger.log(`[PROCESS START] Analyzing email ${data.emailId}`);

    try {
      const email = await this.prisma.email.findUnique({
        where: { id: data.emailId },
        include: { folder: true, attachments: true },
      });

      if (!email) {
        this.logger.warn(`Email ${data.emailId} not found, skipping.`);
        return;
      }

      const mailBox = await this.prisma.mailBox.findUnique({
        where: { id: data.mailBoxId },
        include: { oauthToken: true },
      });

      if (!mailBox) return;

      // 1. Download & Upload Attachments
      if (mailBox.provider === EmailProviders.GMAIL && data.gmailAttachmentParts?.length) {
        const tokens = await this.mailboxesService.getGmailTokens(mailBox.id);
        if (tokens) {
          const oauth2Client = new google.auth.OAuth2();
          oauth2Client.setCredentials({
            access_token: tokens.accessToken,
            refresh_token: tokens.refreshToken,
          });
          const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

          for (const part of data.gmailAttachmentParts) {
            try {
              const body = await this.gmailProvider.getAttachment(gmail, 'me', email.messageId, part.attachmentId);
              if (body.data) {
                const base64Data = body.data.replace(/-/g, '+').replace(/_/g, '/');
                const buffer = Buffer.from(base64Data, 'base64');
                const file = {
                  buffer,
                  originalname: part.filename,
                  mimetype: part.mimeType,
                  size: body.size ?? 0,
                } as Express.Multer.File;

                const stored = await this.attachmentStorage.saveAttachments([file]);
                if (stored.length > 0) {
                  await this.prisma.attachment.create({
                    data: {
                      emailId: email.id,
                      filename: stored[0].filename,
                      mimeType: stored[0].mimeType,
                      size: stored[0].size,
                      storagePath: stored[0].url,
                    },
                  });
                }
              }
            } catch (err) {
              this.logger.error(`Failed to process Gmail attachment ${part.filename}`, err);
            }
          }
        }
      } else if (mailBox.provider === EmailProviders.OUTLOOK && data.outlookHasAttachments) {
        const tokens = await this.mailboxesService.getOutlookTokens(mailBox.id);
        if (tokens) {
          const client = this.outlookProvider.getGraphClient(tokens.accessToken);
          try {
            const raw = await this.outlookProvider.getAttachments(client, email.messageId);
            const attachments = raw.filter((a: any) => a['@odata.type'] === '#microsoft.graph.fileAttachment');
            for (const a of attachments) {
              const buffer = Buffer.from(a.contentBytes, 'base64');
              const file = {
                buffer,
                originalname: a.name,
                mimetype: a.contentType,
                size: a.size,
              } as Express.Multer.File;

              const stored = await this.attachmentStorage.saveAttachments([file]);
              if (stored.length > 0) {
                await this.prisma.attachment.create({
                  data: {
                    emailId: email.id,
                    filename: stored[0].filename,
                    mimeType: stored[0].mimeType,
                    size: stored[0].size,
                    storagePath: stored[0].url,
                  },
                });
              }
            }
          } catch (err) {
            this.logger.error(`Failed to process Outlook attachments`, err);
          }
        }
      }

      // Reload attachments to get complete list
      const finalAttachments = await this.prisma.attachment.findMany({
        where: { emailId: email.id },
      });

      // 2. Build SecurityPipelineInput
      const pipelineInput: SecurityPipelineInput = {
        emailId: email.id,
        messageId: email.messageId,
        mailBoxId: email.mailBoxId,
        fromAddr: email.fromAddr,
        fromName: email.fromName,
        toAddr: (email.toAddr as string[]) ?? [],
        ccAddr: (email.ccAddr as string[]) ?? null,
        bccAddr: (email.bccAddr as string[]) ?? null,
        subject: email.subject,
        bodyText: email.bodyText,
        bodyHtml: email.bodyHtml,
        receivedAt: email.receivedAt,
        attachments: finalAttachments.map(att => ({
          filename: att.filename ?? 'unknown',
          mimeType: att.mimeType ?? 'application/octet-stream',
          size: att.size ?? 0,
          storagePath: att.storagePath,
        })),
      };

      // 3. Security Service Analyze
      const result = await this.securityService.analyze(pipelineInput, data.userId);
      this.logger.debug(`Email ${email.id} analyzed: verdict=${result.verdict.label} score=${result.verdict.riskScore} (${result.processingMs}ms)`);

      // 4. Update status to COMPLETED
      await this.prisma.email.update({
        where: { id: email.id },
        data: { analysisStatus: AnalysisStatus.COMPLETED },
      });

      // 5. If new email & in INBOX, send notification
      if (email.folder.type === FolderType.INBOX) {
        try {
          await this.notificationsService.create({
            userId: data.userId,
            type: NotificationType.NEW_EMAIL_RECEIVED,
            title: 'New Email Received',
            message: `New email: ${email.subject || '(No subject)'}`,
            metadata: {
              emailId: email.id,
              subject: email.subject,
              fromAddr: email.fromAddr,
              verdict: result.verdict.label,
              score: result.verdict.riskScore,
            },
            mailBoxId: data.mailBoxId,
            emailId: email.id,
          });
        } catch { /* ignore */ }
      }

      // 6. Notify Flutter UI that analysis is complete
      this.notificationsService.emitEvent(data.userId, 'email_analyzed', {
        emailId: email.id,
        mailBoxId: data.mailBoxId,
        verdict: result.verdict.label,
        spamScore: result.verdict.riskScore,
        isSpam: result.verdict.label === 'SPAM',
        isPhishing: result.verdict.label === 'PHISHING',
      });

    } catch (err) {
      this.logger.error(`[PROCESS FAILED] Email ${data.emailId}`, err);

      // Check if the email already has a previous completed report (aiReport)
      const existingEmail = await this.prisma.email.findUnique({
        where: { id: data.emailId },
        select: { aiReport: true },
      });

      // If no previous report exists, mark as FAILED. If a report exists, keep COMPLETED.
      if (!existingEmail?.aiReport) {
        await this.prisma.email.update({
          where: { id: data.emailId },
          data: { analysisStatus: AnalysisStatus.FAILED },
        });
      }

      throw err; // Trigger retry
    }
  }
}
