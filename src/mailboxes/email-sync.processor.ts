import { Processor, WorkerHost } from '@nestjs/bullmq';
import { Job } from 'bullmq';
import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma.service';
import { EncryptionService } from '../common/encryption/encryption.service';
import { ClassificationService } from '../classification/classification.service';
import { NotificationsService } from '../notifications/notifications.service';
import { GmailProvider } from './providers/gmail.provider';
import { OutlookProvider } from './providers/outlook.provider';
import { ImapProvider } from './providers/imap.provider';
import { MailboxesService } from './mailboxes.service';
import { EmailProviders } from 'generated/prisma/enums';
import { FolderType } from 'generated/prisma/enums';
import { SyncStatus } from 'generated/prisma/enums';
import { NotificationType } from 'generated/prisma/enums';
import { google } from 'googleapis';

export const EMAIL_SYNC_QUEUE = 'email-sync';

const DEFAULT_STORAGE_LIMIT_BYTES = 1073741824; // 1GB

@Processor(EMAIL_SYNC_QUEUE)
@Injectable()
export class EmailSyncProcessor extends WorkerHost {
  constructor(
    private prisma: PrismaService,
    private encryption: EncryptionService,
    private classificationService: ClassificationService,
    private notificationsService: NotificationsService,
    private configService: ConfigService,
    private gmailProvider: GmailProvider,
    private outlookProvider: OutlookProvider,
    private imapProvider: ImapProvider,
    private mailboxesService: MailboxesService,
  ) {
    super();
  }

  async process(job: Job<{ mailBoxId: number }, void, string>): Promise<void> {
    const { mailBoxId } = job.data;
    try {
      const mailBox = await this.prisma.mailBox.findUnique({
        where: { id: mailBoxId },
        include: { folders: true, oauthToken: true, imapConfig: true },
      });
      if (!mailBox) return;
      if (mailBox.provider === EmailProviders.GMAIL) {
        await this.syncGmail(mailBox);
      } else if (mailBox.provider === EmailProviders.OUTLOOK) {
        await this.syncOutlook(mailBox);
      } else if (mailBox.provider === EmailProviders.CUSTOM) {
        const imapConfig = mailBox.imapConfig;
        if (imapConfig?.passwordEncrypted) {
          await this.syncImap({
            ...mailBox,
            imapConfig: {
              host: imapConfig.host,
              port: imapConfig.port,
              secure: imapConfig.secure,
              passwordEncrypted: imapConfig.passwordEncrypted,
            },
          });
        }
      }
      await this.prisma.syncLog.create({
        data: {
          mailBoxId,
          status: SyncStatus.SUCCESS,
          syncedAt: new Date(),
        },
      });
      await this.prisma.mailBox.update({
        where: { id: mailBoxId },
        data: { lastSyncedAt: new Date() },
      });

      await this.checkLowMailboxSpace(mailBox);
    } catch (err) {
      await this.prisma.syncLog.create({
        data: {
          mailBoxId,
          status: SyncStatus.FAILED,
          errorMessage: err instanceof Error ? err.message : String(err),
          syncedAt: new Date(),
        },
      });
      throw err;
    }
  }

  private async syncGmail(mailBox: {
    id: number;
    userId: number;
    emailAddress: string | null;
    folders: { id: number; remoteId: string; type: string }[];
    oauthToken: { accessTokenEncrypted: string; refreshTokenEncrypted: string } | null;
  }) {
    if (!mailBox.oauthToken) return;
    const tokens = await this.mailboxesService.getGmailTokens(mailBox.id);
    if (!tokens) return;
    const oauth2Client = new google.auth.OAuth2();
    oauth2Client.setCredentials({
      access_token: tokens.accessToken,
      refresh_token: tokens.refreshToken,
    });
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });
    const labelMap: Record<string, string> = {
      INBOX: 'INBOX',
      SENT: 'SENT',
      SPAM: 'SPAM',
    };
    for (const [folderType, labelId] of Object.entries(labelMap)) {
      let folder = mailBox.folders.find((f) => f.type === folderType);
      if (!folder) {
        folder = await this.prisma.folder.create({
          data: {
            mailBoxId: mailBox.id,
            name: folderType.toLowerCase(),
            type: folderType as FolderType,
            remoteId: labelId,
          },
        });
      }
      const { messages } = await this.gmailProvider.listMessages(
        gmail,
        'me',
        [labelId],
        100,
      );
      for (const msg of messages) {
        const full = await this.gmailProvider.getMessage(gmail, 'me', msg.id);
        await this.upsertGmailEmail(
          { id: mailBox.id, userId: mailBox.userId },
          { id: folder.id, type: folder.type },
          full as any,
        );
      }
    }
  }

  private async upsertGmailEmail(
    mailBox: { id: number; userId: number },
    folder: { id: number; type: string },
    msg: { id?: string; payload?: { headers?: Array<{ name?: string; value?: string }>; body?: { data?: string }; parts?: Array<{ mimeType?: string; body?: { data?: string } }> }; internalDate?: string; labelIds?: string[] },
  ) {
    const { id: mailBoxId, userId } = mailBox;
    const folderId = folder.id;
    const getHeader = (name: string) =>
      msg.payload?.headers?.find((h) => h.name?.toLowerCase() === name.toLowerCase())?.value ?? '';
    const messageId = msg.id ?? getHeader('Message-ID') ?? `gmail-${mailBoxId}-${folderId}-${Date.now()}`;
    const from = getHeader('From');
    const to = getHeader('To');
    const cc = getHeader('Cc');
    const bcc = getHeader('Bcc');
    let bodyText = '';
    let bodyHtml = '';
    if (msg.payload?.body?.data) {
      const decoded = Buffer.from(msg.payload.body.data, 'base64').toString('utf8');
      if ((msg.payload as { mimeType?: string }).mimeType === 'text/html') bodyHtml = decoded;
      else bodyText = decoded;
    }
    for (const part of msg.payload?.parts ?? []) {
      if (part.body?.data) {
        const decoded = Buffer.from(part.body.data, 'base64').toString('utf8');
        if (part.mimeType === 'text/html') bodyHtml = decoded;
        else bodyText = decoded;
      }
    }
    const receivedAt = msg.internalDate
      ? new Date(parseInt(msg.internalDate, 10))
      : new Date();
    const isRead = msg.labelIds?.includes('UNREAD') ? false : true;
    const fromName = from.match(/^"([^"]+)"\s*</)?.[1] ?? from.match(/^([^<]+)\s*</)?.[1]?.trim() ?? null;
    const createData = {
      mailBoxId,
      folderId,
      messageId,
      subject: getHeader('Subject'),
      fromAddr: from,
      fromName,
      toAddr: to ? [to] : [],
      ccAddr: cc ? [cc] : [],
      bccAddr: bcc ? [bcc] : [],
      bodyText: bodyText || null,
      bodyHtml: bodyHtml || null,
      isRead,
      isFlagged: msg.labelIds?.includes('STARRED') ?? false,
      isSpam: msg.labelIds?.includes('SPAM') ?? false,
      receivedAt,
    };
    const existing = await this.prisma.email.findUnique({
      where: {
        mailBoxId_folderId_messageId: {
          mailBoxId,
          folderId,
          messageId,
        },
      },
    });
    const email = await this.prisma.email.upsert({
      where: {
        mailBoxId_folderId_messageId: {
          mailBoxId,
          folderId,
          messageId,
        },
      },
      create: createData,
      update: {
        isRead,
        isFlagged: msg.labelIds?.includes('STARRED') ?? false,
        isSpam: msg.labelIds?.includes('SPAM') ?? false,
      },
    });
    const { isPhishing } = await this.classifyAndMove(mailBoxId, email.id, createData);
    const isNew = !existing;

    if (isNew && folder.type === FolderType.INBOX) {
      try {
        await this.notificationsService.create({
          userId,
          type: NotificationType.NEW_EMAIL_RECEIVED,
          title: 'New Email Received',
          message: `New email: ${createData.subject || '(No subject)'}`,
          metadata: {
            emailId: email.id,
            subject: createData.subject,
            fromAddr: createData.fromAddr,
          },
          mailBoxId,
          emailId: email.id,
        });
      } catch {
        // Non-fatal
      }
    }
    if (isPhishing) {
      try {
        await this.notificationsService.create({
          userId,
          type: NotificationType.PHISHING_DETECTED,
          title: 'Phishing Detected',
          message: `Phishing email detected: ${createData.subject || '(No subject)'}`,
          metadata: {
            emailId: email.id,
            subject: createData.subject,
            fromAddr: createData.fromAddr,
          },
          mailBoxId,
          emailId: email.id,
        });
      } catch {
        // Non-fatal
      }
    }
  }

  private async syncOutlook(mailBox: {
    id: number;
    userId: number;
    emailAddress: string | null;
    folders: { id: number; remoteId: string; type: string }[];
    oauthToken: { accessTokenEncrypted: string; refreshTokenEncrypted: string } | null;
  }) {
    if (!mailBox.oauthToken) return;
    const tokens = await this.mailboxesService.getOutlookTokens(mailBox.id);
    if (!tokens) return;
    const client = this.outlookProvider.getGraphClient(tokens.accessToken);
    const folderMap: Record<string, string> = {
      INBOX: 'inbox',
      SENT: 'sentitems',
      SPAM: 'junkemail',
    };
    for (const [type, graphId] of Object.entries(folderMap)) {
      let folder = mailBox.folders.find((f) => f.type === type);
      if (!folder) {
        try {
          const res = await client.api(`/me/mailFolders/${graphId}`).get();
          const remoteId = (res as { id?: string }).id ?? graphId;
          folder = await this.prisma.folder.create({
            data: {
              mailBoxId: mailBox.id,
              name: type.toLowerCase(),
              type: type as FolderType,
              remoteId,
            },
          });
        } catch {
          continue;
        }
      }
      const { messages } = await this.outlookProvider.listMessages(
        client,
        folder.remoteId,
        100,
      );
      for (const m of messages) {
        const full = await this.outlookProvider.getMessage(client, m.id);
        await this.upsertOutlookEmail(
          { id: mailBox.id, userId: mailBox.userId },
          { id: folder.id, type: folder.type },
          full,
        );
      }
    }
  }

  private async upsertOutlookEmail(
    mailBox: { id: number; userId: number },
    folder: { id: number; type: string },
    msg: {
      id?: string;
      subject?: string;
      from?: { emailAddress?: { address?: string; name?: string } };
      toRecipients?: Array<{ emailAddress?: { address?: string; name?: string } }>;
      ccRecipients?: Array<{ emailAddress?: { address?: string; name?: string } }>;
      bccRecipients?: Array<{ emailAddress?: { address?: string; name?: string } }>;
      body?: { content?: string; contentType?: string };
      bodyPreview?: string;
      receivedDateTime?: string;
      isRead?: boolean;
      flag?: { flagStatus?: string };
    },
  ) {
    const { id: mailBoxId, userId } = mailBox;
    const folderId = folder.id;
    const messageId = msg.id ?? `outlook-${mailBoxId}-${folderId}-${Date.now()}`;
    const from = msg.from?.emailAddress
      ? `${msg.from.emailAddress.name ? `"${msg.from.emailAddress.name}" ` : ''}<${msg.from.emailAddress.address}>`
      : '';
    const to = (msg.toRecipients ?? []).map((r) => r.emailAddress?.address ?? '');
    const cc = (msg.ccRecipients ?? []).map((r) => r.emailAddress?.address ?? '');
    const bcc = (msg.bccRecipients ?? []).map((r) => r.emailAddress?.address ?? '');
    const bodyHtml = msg.body?.contentType === 'html' ? msg.body.content : null;
    const bodyText = msg.body?.contentType === 'text' ? msg.body.content : msg.bodyPreview ?? null;
    const receivedAt = msg.receivedDateTime
      ? new Date(msg.receivedDateTime)
      : new Date();
    const fromName = msg.from?.emailAddress?.name ?? null;
    const createData = {
      subject: msg.subject ?? '',
      fromAddr: from,
      fromName,
      bodyText,
      bodyHtml,
    };
    const existingOutlook = await this.prisma.email.findUnique({
      where: {
        mailBoxId_folderId_messageId: {
          mailBoxId,
          folderId,
          messageId,
        },
      },
    });
    const email = await this.prisma.email.upsert({
      where: {
        mailBoxId_folderId_messageId: {
          mailBoxId,
          folderId,
          messageId,
        },
      },
      create: {
        mailBoxId,
        folderId,
        messageId,
        subject: msg.subject ?? '',
        fromAddr: from,
        fromName,
        toAddr: to,
        ccAddr: cc.length ? cc : undefined,
        bccAddr: bcc.length ? bcc : undefined,
        bodyText,
        bodyHtml,
        isRead: msg.isRead ?? false,
        isFlagged: msg.flag?.flagStatus === 'flagged',
        isSpam: false,
        receivedAt,
      },
      update: {
        isRead: msg.isRead ?? false,
        isFlagged: msg.flag?.flagStatus === 'flagged',
      },
    });
    const { isPhishing } = await this.classifyAndMove(mailBoxId, email.id, createData);
    const isNew = !existingOutlook;
    if (isNew && folder.type === FolderType.INBOX) {
      try {
        await this.notificationsService.create({
          userId,
          type: NotificationType.NEW_EMAIL_RECEIVED,
          title: 'New Email Received',
          message: `New email: ${createData.subject || '(No subject)'}`,
          metadata: { emailId: email.id, subject: createData.subject, fromAddr: createData.fromAddr },
          mailBoxId,
          emailId: email.id,
        });
      } catch {}
    }
    if (isPhishing) {
      try {
        await this.notificationsService.create({
          userId,
          type: NotificationType.PHISHING_DETECTED,
          title: 'Phishing Detected',
          message: `Phishing email detected: ${createData.subject || '(No subject)'}`,
          metadata: { emailId: email.id, subject: createData.subject, fromAddr: createData.fromAddr },
          mailBoxId,
          emailId: email.id,
        });
      } catch {}
    }
  }

  private async syncImap(mailBox: {
    id: number;
    userId: number;
    emailAddress: string | null;
    folders: { id: number; remoteId: string; type: string }[];
    imapConfig: { host: string; port: number; secure: boolean; passwordEncrypted: string } | null;
  }) {
    const creds = await this.mailboxesService.getImapCredentials(mailBox.id);
    if (!creds) return;
    const client = await this.imapProvider.connect(creds);
    try {
      const mapping = this.imapProvider.getFolderMapping();
      for (const [type, remotePath] of Object.entries(mapping)) {
        let folder = mailBox.folders.find((f) => f.type === type);
        if (!folder) {
          folder = await this.prisma.folder.create({
            data: {
              mailBoxId: mailBox.id,
              name: type.toLowerCase(),
              type: type as FolderType,
              remoteId: remotePath,
            },
          });
        }
        const messages = await this.imapProvider.fetchMessages(
          client,
          remotePath,
          100,
        );
        for (const msg of messages) {
          const full = await this.imapProvider.fetchFullMessage(
            client,
            remotePath,
            msg.uid,
          );
          const messageId =
            msg.envelope.messageId ?? `imap-${mailBox.id}-${folder.id}-${msg.uid}`;
          const from = msg.envelope.from?.[0]
            ? `${msg.envelope.from[0].name ? `"${msg.envelope.from[0].name}" ` : ''}<${msg.envelope.from[0].address}>`
            : full.from;
          const to = (msg.envelope.to ?? []).map((a) => a.address ?? '');
          const cc = (msg.envelope.cc ?? []).map((a) => a.address ?? '');
          const bcc = (msg.envelope.bcc ?? []).map((a) => a.address ?? '');
          const receivedAt = msg.envelope.date ?? full.date ?? new Date();
          const createData = {
            subject: msg.envelope.subject ?? full.subject ?? '',
            fromAddr: from,
            fromName: msg.envelope.from?.[0]?.name ?? null,
            bodyText: full.text ?? null,
            bodyHtml: full.html ?? null,
          };
          const existingImap = await this.prisma.email.findUnique({
            where: {
              mailBoxId_folderId_messageId: {
                mailBoxId: mailBox.id,
                folderId: folder.id,
                messageId,
              },
            },
          });
          const email = await this.prisma.email.upsert({
            where: {
              mailBoxId_folderId_messageId: {
                mailBoxId: mailBox.id,
                folderId: folder.id,
                messageId,
              },
            },
            create: {
              mailBoxId: mailBox.id,
              folderId: folder.id,
              messageId,
              subject: msg.envelope.subject ?? full.subject ?? '',
              fromAddr: from,
              toAddr: to.length ? to : [full.to.join(', ')],
              ccAddr: cc.length ? cc : (full.cc?.length ? full.cc : undefined),
              bccAddr: bcc.length ? bcc : (full.bcc?.length ? full.bcc : undefined),
              bodyText: full.text ?? null,
              bodyHtml: full.html ?? null,
              isRead: msg.flags.has('\\Seen'),
              isFlagged: msg.flags.has('\\Flagged'),
              isSpam: type === 'SPAM',
              receivedAt,
            },
            update: {
              isRead: msg.flags.has('\\Seen'),
              isFlagged: msg.flags.has('\\Flagged'),
            },
          });
          const { isPhishing } = await this.classifyAndMove(mailBox.id, email.id, createData);
          const isNew = !existingImap;
          if (isNew && type === 'INBOX') {
            try {
              await this.notificationsService.create({
                userId: mailBox.userId,
                type: NotificationType.NEW_EMAIL_RECEIVED,
                title: 'New Email Received',
                message: `New email: ${createData.subject || '(No subject)'}`,
                metadata: { emailId: email.id, subject: createData.subject, fromAddr: createData.fromAddr },
                mailBoxId: mailBox.id,
                emailId: email.id,
              });
            } catch {}
          }
          if (isPhishing) {
            try {
              await this.notificationsService.create({
                userId: mailBox.userId,
                type: NotificationType.PHISHING_DETECTED,
                title: 'Phishing Detected',
                message: `Phishing email detected: ${createData.subject || '(No subject)'}`,
                metadata: { emailId: email.id, subject: createData.subject, fromAddr: createData.fromAddr },
                mailBoxId: mailBox.id,
                emailId: email.id,
              });
            } catch {}
          }
        }
      }
    } finally {
      await client.logout();
    }
  }

  private async classifyAndMove(
    mailBoxId: number,
    emailId: number,
    emailData: {
      subject: string;
      fromAddr: string;
      fromName?: string | null;
      bodyText?: string | null;
      bodyHtml?: string | null;
    },
  ): Promise<{ isPhishing: boolean }> {
    const result = this.classificationService.classify({
      subject: emailData.subject,
      fromAddr: emailData.fromAddr,
      fromName: emailData.fromName ?? undefined,
      bodyText: emailData.bodyText,
      bodyHtml: emailData.bodyHtml,
    });

    const updateData: {
      spamScore: number;
      phishingScore: number;
      isSpam?: boolean;
      isPhishing?: boolean;
      folderId?: number;
    } = {
      spamScore: result.spamScore,
      phishingScore: result.phishingScore,
    };

    if (result.isPhishing) {
      const phishingFolder = await this.getOrCreateFolder(mailBoxId, FolderType.PHISHING);
      updateData.folderId = phishingFolder.id;
      updateData.isPhishing = true;
    } else if (result.isSpam) {
      const spamFolder = await this.getOrCreateFolder(mailBoxId, FolderType.SPAM);
      updateData.folderId = spamFolder.id;
      updateData.isSpam = true;
    }

    await this.prisma.email.update({
      where: { id: emailId },
      data: updateData,
    });

    return { isPhishing: !!result.isPhishing };
  }

  private async checkLowMailboxSpace(mailBox: { id: number; userId: number }): Promise<void> {
    const limitBytes =
      this.configService.get<number>('MAILBOX_STORAGE_LIMIT_BYTES') ??
      DEFAULT_STORAGE_LIMIT_BYTES;
    const threshold = 0.8;

    const result = await this.prisma.attachment.aggregate({
      where: {
        email: { mailBoxId: mailBox.id },
      },
      _sum: { size: true },
    });
    const usedBytes = result._sum.size ?? 0;
    const usagePercent = usedBytes / limitBytes;

    if (usagePercent >= threshold) {
      try {
        await this.notificationsService.create({
          userId: mailBox.userId,
          type: NotificationType.LOW_MAILBOX_SPACE,
          title: 'Low Mailbox Space',
          message: `Your mailbox storage is at ${Math.round(usagePercent * 100)}%. Consider cleaning up.`,
          metadata: {
            mailBoxId: mailBox.id,
            usedBytes,
            limitBytes,
            usagePercent,
          },
          mailBoxId: mailBox.id,
        });
      } catch {
        // Non-fatal
      }
    }
  }

  private async getOrCreateFolder(
    mailBoxId: number,
    type: FolderType,
  ) {
    let folder = await this.prisma.folder.findFirst({
      where: { mailBoxId, type },
    });
    if (!folder) {
      folder = await this.prisma.folder.create({
        data: {
          mailBoxId,
          name: type.toLowerCase(),
          type,
          remoteId: type,
        },
      });
    }
    return folder;
  }
}
