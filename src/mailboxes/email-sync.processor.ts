// ─────────────────────────────────────────────────────────────────────────────
// mailboxes/email-sync.processor.ts  (UPDATED v3)
//
// Email Sync Processor — BullMQ Worker
//
// Notification responsibility split:
//   - NEW_EMAIL_RECEIVED       → processor (only it knows if email is new)
//   - MALWARE_DETECTED         → SecurityService
//   - PHISHING_DETECTED        → SecurityService
//   - BEHAVIORAL_ANOMALY       → SecurityService
//   - LOW_MAILBOX_SPACE        → processor (storage check is in sync, not security)
// ─────────────────────────────────────────────────────────────────────────────

import { Processor, WorkerHost, InjectQueue } from '@nestjs/bullmq';
import { Job, Queue } from 'bullmq';
import { Injectable, Logger } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { PrismaService } from '../prisma.service';
import { NotificationsService } from '../notifications/notifications.service';
import { GmailProvider } from './providers/gmail.provider';
import { OutlookProvider } from './providers/outlook.provider';
import { ImapProvider } from './providers/imap.provider';
import { MailboxesService } from './mailboxes.service';
import { EmailProviders, FolderType, SyncStatus, NotificationType } from '@prisma/client';
import { google, gmail_v1 } from 'googleapis';
import { QUEUE_EMAIL_SYNC, QUEUE_EMAIL_PROCESS } from '../common/constants/queues';
import { AttachmentStorageService } from './emails/attachment-storage.service';
import { Client } from '@microsoft/microsoft-graph-client';

export const EMAIL_SYNC_QUEUE = QUEUE_EMAIL_SYNC;

const DEFAULT_STORAGE_LIMIT_BYTES = 1073741824; // 1GB

// ─── Internal email data shape (provider-agnostic) ───────────────────────────
interface NormalizedEmailData {
  messageId: string;
  subject: string;
  fromAddr: string;
  fromName: string | null;
  toAddr: string[];
  ccAddr?: string[];
  bccAddr?: string[];
  bodyText: string | null;
  bodyHtml: string | null;
  receivedAt: Date;
  isRead: boolean;
  isFlagged: boolean;
  isSpam: boolean;
  attachments?: Array<{
    filename: string;
    mimeType: string;
    size: number;
    content: Buffer;
  }>;
}

export interface ProcessEmailJobData {
  emailId: number;
  mailBoxId: number;
  userId: number;
  messageId: string;
  gmailAttachmentParts?: Array<{ filename: string; mimeType: string; attachmentId: string }>;
  outlookHasAttachments?: boolean;
  existingAttachmentIds?: number[];
}

@Processor(EMAIL_SYNC_QUEUE, { concurrency: 5 })
@Injectable()
export class EmailSyncProcessor extends WorkerHost {
  private readonly logger = new Logger(EmailSyncProcessor.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly notificationsService: NotificationsService,
    private readonly configService: ConfigService,
    private readonly gmailProvider: GmailProvider,
    private readonly outlookProvider: OutlookProvider,
    private readonly imapProvider: ImapProvider,
    private readonly mailboxesService: MailboxesService,
    private readonly attachmentStorage: AttachmentStorageService,
    @InjectQueue(QUEUE_EMAIL_PROCESS) private readonly processQueue: Queue,
  ) {
    super();
    this.logger.log('EmailSyncProcessor initialized and waiting for jobs...');
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MAIN WORKER ENTRY POINT
  // ═══════════════════════════════════════════════════════════════════════════

  async process(job: Job<{ mailBoxId: number }, void, string>): Promise<void> {
    const { mailBoxId } = job.data;
    this.logger.log(`[SYNC START] Processing sync for mailbox ${mailBoxId}...`);
    try {
      const mailBox = await this.prisma.mailBox.findUnique({
        where: { id: mailBoxId },
        include: { folders: true, oauthToken: true, imapConfig: true },
      });
      if (!mailBox) {
        this.logger.warn(`[SYNC] Mailbox ${mailBoxId} not found, skipping.`);
        return;
      }

      this.logger.log(`[SYNC] Provider: ${mailBox.provider} for ${mailBox.emailAddress}`);
      this.logger.log(`[SYNC] Last synced at: ${mailBox.lastSyncedAt?.toISOString() ?? 'Never'}`);

      // ── Notify Flutter that sync has started ──────────────────────────────
      this.notificationsService.emitEvent(mailBox.userId, 'mailbox_sync_start', {
        mailBoxId,
      });

      if (mailBox.provider === EmailProviders.GMAIL) {
        await this.syncGmail(mailBox);
      } else if (mailBox.provider === EmailProviders.OUTLOOK) {
        await this.syncOutlook(mailBox);
      } else if (mailBox.provider === EmailProviders.CUSTOM) {
        const cfg = mailBox.imapConfig;
        if (cfg?.passwordEncrypted) {
          await this.syncImap({
            ...mailBox,
            imapConfig: {
              host: cfg.host,
              port: cfg.port,
              secure: cfg.secure,
              passwordEncrypted: cfg.passwordEncrypted,
            },
          });
        }
      }

      await this.prisma.syncLog.create({
        data: { mailBoxId, status: SyncStatus.SUCCESS, syncedAt: new Date() },
      });
      await this.prisma.mailBox.update({
        where: { id: mailBoxId },
        data: { lastSyncedAt: new Date() },
      });
      this.logger.log(`[SYNC SUCCESS] Finished sync for mailbox ${mailBoxId}`);
      await this.checkLowMailboxSpace(mailBox);

      // ── Notify Flutter to refresh emails via WebSocket ──────────────────────
      this.notificationsService.emitEvent(mailBox.userId, 'mailbox_sync_complete', {
        mailBoxId,
        success: true,
      });

    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : String(err);
      this.logger.error(`[SYNC FAILED] Mailbox ${mailBoxId}: ${errorMessage}`, err instanceof Error ? err.stack : undefined);
      await this.prisma.syncLog.create({
        data: {
          mailBoxId,
          status: SyncStatus.FAILED,
          errorMessage,
          syncedAt: new Date(),
        },
      });

      // Notify user about the sync failure
      const mailBox = await this.prisma.mailBox.findUnique({ where: { id: mailBoxId } });
      if (mailBox) {
        await this.notificationsService.create({
          userId: mailBox.userId,
          type: NotificationType.FAILED_SYNC,
          title: 'Mailbox Sync Failed',
          message: `Sync failed for ${mailBox.emailAddress}: ${errorMessage}`,
          mailBoxId: mailBox.id,
        });
        // Dismiss the syncing indicator in Flutter
        this.notificationsService.emitEvent(mailBox.userId, 'mailbox_sync_complete', {
          mailBoxId,
          success: false,
        });
      }
      throw err;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // GMAIL SYNC
  // ═══════════════════════════════════════════════════════════════════════════

  private async syncGmail(mailBox: {
    id: number; userId: number; emailAddress: string | null;
    lastSyncedAt: Date | null;
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

    // Determine if this is a first-ever sync by checking actual email count in DB
    const emailCount = await this.prisma.email.count({ where: { mailBoxId: mailBox.id } });
    const isFirstSync = emailCount === 0;

    // Total email budget shared across all folders
    const TOTAL_LIMIT = 100;

    // We removed the 'after' query filter to avoid "sync gaps" caused by the 100-email limit.
    // Instead, we always fetch the latest 100 messages and let processGmailMessage handle deduplication.
    const query: string | undefined = undefined;
    this.logger.log(`[SYNC] Fetching latest ${TOTAL_LIMIT} messages for mailbox ${mailBox.id} (Deduplication handled per-message)`);
    // Per-folder limits (must sum to TOTAL_LIMIT)
    const folderLimits: Record<string, number> = {
      INBOX: 70,
      SENT: 20,
      SPAM: 10,
    };
    let fetchedTotal = 0;

    for (const [folderType, labelId] of Object.entries(labelMap)) {
      if (fetchedTotal >= TOTAL_LIMIT) break;

      // ── Use upsert logic to prevent duplicate folder creation ──────────────
      let folder = await this.prisma.folder.findFirst({
        where: { mailBoxId: mailBox.id, type: folderType as FolderType },
      });
      if (!folder) {
        folder = await this.prisma.folder.create({
          data: { mailBoxId: mailBox.id, name: folderType.toLowerCase(), type: folderType as FolderType, remoteId: labelId },
        });
      }

      const remaining = Math.min(folderLimits[folderType] ?? 10, TOTAL_LIMIT - fetchedTotal);
      const { messages } = await this.gmailProvider.listMessages(gmail, 'me', [labelId], remaining, undefined, query);

      this.logger.log(`[SYNC] Found ${messages.length} messages in label ${labelId} (budget: ${remaining})`);

      const BATCH_SIZE = 10;
      for (let i = 0; i < messages.length; i += BATCH_SIZE) {
        const batch = messages.slice(i, i + BATCH_SIZE);
        await Promise.all(batch.map(async (msg) => {
          try {
            const full = await this.gmailProvider.getMessage(gmail, 'me', msg.id);
            await this.processGmailMessage(
              { id: mailBox.id, userId: mailBox.userId },
              { id: folder.id, type: folder.type },
              full as any,
              gmail,
            );
          } catch (err) {
            this.logger.error(`Error processing Gmail message ${msg.id}`, err);
          }
        }));
        fetchedTotal += batch.length;
        if (fetchedTotal >= TOTAL_LIMIT) break;
      }
    }
  }

  private async processGmailMessage(
    mailBox: { id: number; userId: number },
    folder: { id: number; type: string },
    msg: {
      id?: string;
      payload?: { headers?: Array<{ name?: string; value?: string }>; body?: { data?: string }; parts?: Array<{ mimeType?: string; filename?: string; body?: { data?: string; attachmentId?: string }; parts?: any[] }> };
      internalDate?: string;
      labelIds?: string[];
    },
    gmail: gmail_v1.Gmail,
  ) {
    const getHeader = (name: string) =>
      msg.payload?.headers?.find(h => h.name?.toLowerCase() === name.toLowerCase())?.value ?? '';

    const messageId = msg.id ?? getHeader('Message-ID') ?? `gmail-${mailBox.id}-${folder.id}-${Date.now()}`;
    const from = getHeader('From');
    let bodyText = '', bodyHtml = '';

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

    const gmailAttachmentParts: Array<{ filename: string; mimeType: string; attachmentId: string }> = [];
    const collectParts = (parts: any[]) => {
      for (const part of parts) {
        if (part.filename && part.body?.attachmentId) {
          gmailAttachmentParts.push({
            filename: part.filename,
            mimeType: part.mimeType,
            attachmentId: part.body.attachmentId,
          });
        } else if (part.parts) {
          collectParts(part.parts);
        }
      }
    };
    collectParts(msg.payload?.parts ?? []);

    const normalized: NormalizedEmailData = {
      messageId,
      subject: getHeader('Subject'),
      fromAddr: from,
      fromName: from.match(/^"([^"]+)"\s*</)?.[1] ?? from.match(/^([^<]+)\s*</)?.[1]?.trim() ?? null,
      toAddr: [getHeader('To')].filter(Boolean),
      ccAddr: getHeader('Cc') ? [getHeader('Cc')] : undefined,
      bccAddr: getHeader('Bcc') ? [getHeader('Bcc')] : undefined,
      bodyText: bodyText || null,
      bodyHtml: bodyHtml || null,
      receivedAt: msg.internalDate ? new Date(parseInt(msg.internalDate, 10)) : new Date(),
      isRead: !(msg.labelIds?.includes('UNREAD') ?? false),
      isFlagged: msg.labelIds?.includes('STARRED') ?? false,
      isSpam: msg.labelIds?.includes('SPAM') ?? false,
    };

    await this.upsertAndEnqueue(mailBox, folder, normalized, { gmailAttachmentParts });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // OUTLOOK SYNC
  // ═══════════════════════════════════════════════════════════════════════════

  private async syncOutlook(mailBox: {
    id: number; userId: number; emailAddress: string | null;
    lastSyncedAt: Date | null;
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
      let folder = mailBox.folders.find(f => f.type === type);
      if (!folder) {
        try {
          const res = await client.api(`/me/mailFolders/${graphId}`).get();
          const remoteId = (res as { id?: string }).id ?? graphId;
          folder = await this.prisma.folder.create({
            data: { mailBoxId: mailBox.id, name: type.toLowerCase(), type: type as FolderType, remoteId },
          });
        } catch { continue; }
      }

      const { messages } = await this.outlookProvider.listMessages(client, folder.remoteId, 100);

      const BATCH_SIZE = 10;
      for (let i = 0; i < messages.length; i += BATCH_SIZE) {
        const batch = messages.slice(i, i + BATCH_SIZE);
        await Promise.all(batch.map(async (m) => {
          try {
            const full = await this.outlookProvider.getMessage(client, m.id);
            await this.processOutlookMessage(
              { id: mailBox.id, userId: mailBox.userId },
              { id: folder.id, type: folder.type },
              full,
              client,
            );
          } catch (err) {
            this.logger.error(`Error processing Outlook message ${m.id}`, err);
          }
        }));
      }
    }
  }

  private async processOutlookMessage(
    mailBox: { id: number; userId: number },
    folder: { id: number; type: string },
    msg: {
      id?: string; subject?: string;
      from?: { emailAddress?: { address?: string; name?: string } };
      toRecipients?: Array<{ emailAddress?: { address?: string } }>;
      ccRecipients?: Array<{ emailAddress?: { address?: string } }>;
      bccRecipients?: Array<{ emailAddress?: { address?: string } }>;
      body?: { content?: string; contentType?: string };
      bodyPreview?: string; receivedDateTime?: string;
      isRead?: boolean; flag?: { flagStatus?: string };
      hasAttachments?: boolean;
    },
    client: Client,
  ) {
    const from = msg.from?.emailAddress
      ? `${msg.from.emailAddress.name ? `"${msg.from.emailAddress.name}" ` : ''}<${msg.from.emailAddress.address}>`
      : '';

    const normalized: NormalizedEmailData = {
      messageId: msg.id ?? `outlook-${mailBox.id}-${folder.id}-${Date.now()}`,
      subject: msg.subject ?? '',
      fromAddr: from,
      fromName: msg.from?.emailAddress?.name ?? null,
      toAddr: (msg.toRecipients ?? []).map(r => r.emailAddress?.address ?? '').filter(Boolean),
      ccAddr: (msg.ccRecipients ?? []).map(r => r.emailAddress?.address ?? '').filter(Boolean),
      bccAddr: (msg.bccRecipients ?? []).map(r => r.emailAddress?.address ?? '').filter(Boolean),
      bodyText: msg.body?.contentType === 'text' ? msg.body.content ?? null : msg.bodyPreview ?? null,
      bodyHtml: msg.body?.contentType === 'html' ? msg.body.content ?? null : null,
      receivedAt: msg.receivedDateTime ? new Date(msg.receivedDateTime) : new Date(),
      isRead: msg.isRead ?? false,
      isFlagged: msg.flag?.flagStatus === 'flagged',
      isSpam: false,
      attachments: [],
    };

    await this.upsertAndEnqueue(mailBox, folder, normalized, { outlookHasAttachments: msg.hasAttachments });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // IMAP SYNC
  // ═══════════════════════════════════════════════════════════════════════════

  private async syncImap(mailBox: {
    id: number; userId: number; emailAddress: string | null;
    folders: { id: number; remoteId: string; type: string }[];
    imapConfig: { host: string; port: number; secure: boolean; passwordEncrypted: string } | null;
  }) {
    const creds = await this.mailboxesService.getImapCredentials(mailBox.id);
    if (!creds) return;

    const client = await this.imapProvider.connect(creds);
    try {
      const mapping = this.imapProvider.getFolderMapping();

      for (const [type, remotePath] of Object.entries(mapping)) {
        let folder = mailBox.folders.find(f => f.type === type);
        if (!folder) {
          folder = await this.prisma.folder.create({
            data: { mailBoxId: mailBox.id, name: type.toLowerCase(), type: type as FolderType, remoteId: remotePath },
          });
        }

        const messages = await this.imapProvider.fetchMessages(client, remotePath, 100);

        const BATCH_SIZE = 10;
        for (let i = 0; i < messages.length; i += BATCH_SIZE) {
          const batch = messages.slice(i, i + BATCH_SIZE);
          await Promise.all(batch.map(async (msg) => {
            try {
              const full      = await this.imapProvider.fetchFullMessage(client, remotePath, msg.uid);
              const messageId = msg.envelope.messageId ?? `imap-${mailBox.id}-${folder.id}-${msg.uid}`;
              const from      = msg.envelope.from?.[0]
                ? `${msg.envelope.from[0].name ? `"${msg.envelope.from[0].name}" ` : ''}<${msg.envelope.from[0].address}>`
                : full.from;
    
              const normalized: NormalizedEmailData = {
                messageId,
                subject:   msg.envelope.subject ?? full.subject ?? '',
                fromAddr:  from,
                fromName:  msg.envelope.from?.[0]?.name ?? null,
                toAddr:    (msg.envelope.to ?? []).map(a => a.address ?? '').filter(Boolean),
                ccAddr:    (msg.envelope.cc ?? []).map(a => a.address ?? '').filter(Boolean),
                bccAddr:   (msg.envelope.bcc ?? []).map(a => a.address ?? '').filter(Boolean),
                bodyText:  full.text ?? null,
                bodyHtml:  full.html ?? null,
                receivedAt: msg.envelope.date ?? full.date ?? new Date(),
                isRead:    msg.flags.has('\\Seen'),
                isFlagged: msg.flags.has('\\Flagged'),
                isSpam:    type === 'SPAM',
                attachments: full.attachments,
              };
    
              await this.upsertAndEnqueue(
                { id: mailBox.id, userId: mailBox.userId },
                { id: folder.id, type: folder.type },
                normalized,
                {}
              );
            } catch (err) {
              this.logger.error(`Error processing IMAP message ${msg.uid}`, err);
            }
          }));
        }
      }
    } finally {
      await client.logout();
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // CORE: upsertAndAnalyze — provider-agnostic email persistence + analysis
  // ═══════════════════════════════════════════════════════════════════════════

  /**
   * upsertAndEnqueue()
   *
   * 1. Upsert email record into DB (status: PENDING_ANALYSIS)
   * 2. Save attachments for IMAP (since they are already in memory)
   * 3. Queue the background processing job
   */
  private async upsertAndEnqueue(
    mailBox: { id: number; userId: number },
    folder: { id: number; type: string },
    data: NormalizedEmailData,
    jobData: Partial<ProcessEmailJobData>
  ): Promise<void> {
    const { id: mailBoxId, userId } = mailBox;
    const folderId = folder.id;
    const messageId = data.messageId;

    const existing = await this.prisma.email.findFirst({
      where: { mailBoxId, messageId },
    });

    if (existing) {
      await this.prisma.email.update({
        where: { id: existing.id },
        data: {
          isRead: data.isRead,
          isFlagged: data.isFlagged,
        },
      });
      return;
    }

    const email = await this.prisma.email.create({
      data: {
        mailBoxId, folderId, messageId,
        subject: data.subject,
        fromAddr: data.fromAddr,
        fromName: data.fromName,
        toAddr: data.toAddr,
        ccAddr: data.ccAddr?.length ? data.ccAddr : undefined,
        bccAddr: data.bccAddr?.length ? data.bccAddr : undefined,
        bodyText: data.bodyText,
        bodyHtml: data.bodyHtml,
        isRead: data.isRead,
        isFlagged: data.isFlagged,
        isSpam: data.isSpam,
        receivedAt: data.receivedAt,
        analysisStatus: 'PENDING',
      },
    });

    // Handle IMAP attachments (already downloaded)
    if (data.attachments?.length) {
      for (const att of data.attachments) {
        const file = {
          buffer: att.content,
          originalname: att.filename,
          mimetype: att.mimeType,
          size: att.size,
        } as Express.Multer.File;

        try {
          const stored = await this.attachmentStorage.saveAttachments([file]);
          if (stored.length > 0) {
            const createdAtt = await this.prisma.attachment.create({
              data: {
                emailId: email.id,
                filename: stored[0].filename,
                mimeType: stored[0].mimeType,
                size: stored[0].size,
                storagePath: stored[0].url,
              },
            });
            if (!jobData.existingAttachmentIds) jobData.existingAttachmentIds = [];
            jobData.existingAttachmentIds.push(createdAtt.id);
          }
        } catch (err) {
          this.logger.error(`Failed to save attachment ${att.filename} for email ${email.id}`, err);
        }
      }
    }

    await this.processQueue.add('process-email', {
      emailId: email.id,
      mailBoxId,
      userId,
      messageId,
      ...jobData
    }, { jobId: `process-${email.id}` });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // STORAGE CHECK
  // ═══════════════════════════════════════════════════════════════════════════

  private async checkLowMailboxSpace(mailBox: { id: number; userId: number }): Promise<void> {
    const limitBytes = this.configService.get<number>('MAILBOX_STORAGE_LIMIT_BYTES') ?? DEFAULT_STORAGE_LIMIT_BYTES;
    const threshold = 0.8;

    const result = await this.prisma.attachment.aggregate({
      where: { email: { mailBoxId: mailBox.id } },
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
          message: `Mailbox storage at ${Math.round(usagePercent * 100)}%. Consider cleaning up.`,
          metadata: { mailBoxId: mailBox.id, usedBytes, limitBytes, usagePercent },
          mailBoxId: mailBox.id,
        });
      } catch { /* Non-fatal */ }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // FOLDER HELPER
  // ═══════════════════════════════════════════════════════════════════════════

  private async getOrCreateFolder(mailBoxId: number, type: FolderType) {
    let folder = await this.prisma.folder.findFirst({ where: { mailBoxId, type } });
    if (!folder) {
      folder = await this.prisma.folder.create({
        data: { mailBoxId, name: type.toLowerCase(), type, remoteId: type },
      });
    }
    return folder;
  }
}
