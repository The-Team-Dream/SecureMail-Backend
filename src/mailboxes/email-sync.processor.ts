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

import { Processor, WorkerHost }   from '@nestjs/bullmq';
import { Job }                      from 'bullmq';
import { Injectable, Logger }       from '@nestjs/common';
import { ConfigService }            from '@nestjs/config';
import { PrismaService }            from '../prisma.service';
import { EncryptionService }        from '../common/encryption/encryption.service';
import { NotificationsService }     from '../notifications/notifications.service';
import { GmailProvider }            from './providers/gmail.provider';
import { OutlookProvider }          from './providers/outlook.provider';
import { ImapProvider }             from './providers/imap.provider';
import { MailboxesService }         from './mailboxes.service';
import { SecurityService, SecurityPipelineInput } from '../security/security.service';
import { EmailProviders, FolderType, SyncStatus, NotificationType } from '@prisma/client';
import { google }                   from 'googleapis';
import { QUEUE_EMAIL_SYNC }         from '../common/constants/queues';

export const EMAIL_SYNC_QUEUE = QUEUE_EMAIL_SYNC;

const DEFAULT_STORAGE_LIMIT_BYTES = 1073741824; // 1GB

// ─── Internal email data shape (provider-agnostic) ───────────────────────────
interface NormalizedEmailData {
  messageId:  string;
  subject:    string;
  fromAddr:   string;
  fromName:   string | null;
  toAddr:     string[];
  ccAddr?:    string[];
  bccAddr?:   string[];
  bodyText:   string | null;
  bodyHtml:   string | null;
  receivedAt: Date;
  isRead:     boolean;
  isFlagged:  boolean;
  isSpam:     boolean;
}

@Processor(EMAIL_SYNC_QUEUE, { concurrency: 5 })
@Injectable()
export class EmailSyncProcessor extends WorkerHost {
  private readonly logger = new Logger(EmailSyncProcessor.name);

  constructor(
    private readonly prisma:               PrismaService,
    private readonly encryption:           EncryptionService,
    private readonly securityService:      SecurityService,        // ← replaces classificationService
    private readonly notificationsService: NotificationsService,
    private readonly configService:        ConfigService,
    private readonly gmailProvider:        GmailProvider,
    private readonly outlookProvider:      OutlookProvider,
    private readonly imapProvider:         ImapProvider,
    private readonly mailboxesService:     MailboxesService,
  ) {
    super();
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MAIN WORKER ENTRY POINT
  // ═══════════════════════════════════════════════════════════════════════════

  async process(job: Job<{ mailBoxId: number }, void, string>): Promise<void> {
    const { mailBoxId } = job.data;
    try {
      const mailBox = await this.prisma.mailBox.findUnique({
        where:   { id: mailBoxId },
        include: { folders: true, oauthToken: true, imapConfig: true },
      });
      if (!mailBox) return;

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
              host:              cfg.host,
              port:              cfg.port,
              secure:            cfg.secure,
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
        data:  { lastSyncedAt: new Date() },
      });
      await this.checkLowMailboxSpace(mailBox);

    } catch (err) {
      await this.prisma.syncLog.create({
        data: {
          mailBoxId,
          status:       SyncStatus.FAILED,
          errorMessage: err instanceof Error ? err.message : String(err),
          syncedAt:     new Date(),
        },
      });
      throw err;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // GMAIL SYNC
  // ═══════════════════════════════════════════════════════════════════════════

  private async syncGmail(mailBox: {
    id: number; userId: number; emailAddress: string | null;
    folders: { id: number; remoteId: string; type: string }[];
    oauthToken: { accessTokenEncrypted: string; refreshTokenEncrypted: string } | null;
  }) {
    if (!mailBox.oauthToken) return;
    const tokens = await this.mailboxesService.getGmailTokens(mailBox.id);
    if (!tokens) return;

    const oauth2Client = new google.auth.OAuth2();
    oauth2Client.setCredentials({
      access_token:  tokens.accessToken,
      refresh_token: tokens.refreshToken,
    });
    const gmail = google.gmail({ version: 'v1', auth: oauth2Client });

    const labelMap: Record<string, string> = {
      INBOX: 'INBOX',
      SENT:  'SENT',
      SPAM:  'SPAM',
    };

    for (const [folderType, labelId] of Object.entries(labelMap)) {
      let folder = mailBox.folders.find(f => f.type === folderType);
      if (!folder) {
        folder = await this.prisma.folder.create({
          data: { mailBoxId: mailBox.id, name: folderType.toLowerCase(), type: folderType as FolderType, remoteId: labelId },
        });
      }

      const { messages } = await this.gmailProvider.listMessages(gmail, 'me', [labelId], 1000);

      for (const msg of messages) {
        const full = await this.gmailProvider.getMessage(gmail, 'me', msg.id);
        await this.processGmailMessage(
          { id: mailBox.id, userId: mailBox.userId },
          { id: folder.id, type: folder.type },
          full as any,
        );
      }
    }
  }

  private async processGmailMessage(
    mailBox: { id: number; userId: number },
    folder:  { id: number; type: string },
    msg:     {
      id?: string;
      payload?: { headers?: Array<{ name?: string; value?: string }>; body?: { data?: string }; parts?: Array<{ mimeType?: string; body?: { data?: string } }> };
      internalDate?: string;
      labelIds?: string[];
    },
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

    const normalized: NormalizedEmailData = {
      messageId,
      subject:    getHeader('Subject'),
      fromAddr:   from,
      fromName:   from.match(/^"([^"]+)"\s*</)?.[1] ?? from.match(/^([^<]+)\s*</)?.[1]?.trim() ?? null,
      toAddr:     [getHeader('To')].filter(Boolean),
      ccAddr:     getHeader('Cc') ? [getHeader('Cc')] : undefined,
      bccAddr:    getHeader('Bcc') ? [getHeader('Bcc')] : undefined,
      bodyText:   bodyText || null,
      bodyHtml:   bodyHtml || null,
      receivedAt: msg.internalDate ? new Date(parseInt(msg.internalDate, 10)) : new Date(),
      isRead:     !(msg.labelIds?.includes('UNREAD') ?? false),
      isFlagged:  msg.labelIds?.includes('STARRED') ?? false,
      isSpam:     msg.labelIds?.includes('SPAM') ?? false,
    };

    await this.upsertAndAnalyze(mailBox, folder, normalized);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // OUTLOOK SYNC
  // ═══════════════════════════════════════════════════════════════════════════

  private async syncOutlook(mailBox: {
    id: number; userId: number; emailAddress: string | null;
    folders: { id: number; remoteId: string; type: string }[];
    oauthToken: { accessTokenEncrypted: string; refreshTokenEncrypted: string } | null;
  }) {
    if (!mailBox.oauthToken) return;
    const tokens = await this.mailboxesService.getOutlookTokens(mailBox.id);
    if (!tokens) return;

    const client = this.outlookProvider.getGraphClient(tokens.accessToken);
    const folderMap: Record<string, string> = {
      INBOX: 'inbox',
      SENT:  'sentitems',
      SPAM:  'junkemail',
    };

    for (const [type, graphId] of Object.entries(folderMap)) {
      let folder = mailBox.folders.find(f => f.type === type);
      if (!folder) {
        try {
          const res    = await client.api(`/me/mailFolders/${graphId}`).get();
          const remoteId = (res as { id?: string }).id ?? graphId;
          folder = await this.prisma.folder.create({
            data: { mailBoxId: mailBox.id, name: type.toLowerCase(), type: type as FolderType, remoteId },
          });
        } catch { continue; }
      }

      const { messages } = await this.outlookProvider.listMessages(client, folder.remoteId, 100);

      for (const m of messages) {
        const full = await this.outlookProvider.getMessage(client, m.id);
        await this.processOutlookMessage(
          { id: mailBox.id, userId: mailBox.userId },
          { id: folder.id, type: folder.type },
          full,
        );
      }
    }
  }

  private async processOutlookMessage(
    mailBox: { id: number; userId: number },
    folder:  { id: number; type: string },
    msg:     {
      id?: string; subject?: string;
      from?: { emailAddress?: { address?: string; name?: string } };
      toRecipients?:  Array<{ emailAddress?: { address?: string } }>;
      ccRecipients?:  Array<{ emailAddress?: { address?: string } }>;
      bccRecipients?: Array<{ emailAddress?: { address?: string } }>;
      body?: { content?: string; contentType?: string };
      bodyPreview?: string; receivedDateTime?: string;
      isRead?: boolean; flag?: { flagStatus?: string };
    },
  ) {
    const from = msg.from?.emailAddress
      ? `${msg.from.emailAddress.name ? `"${msg.from.emailAddress.name}" ` : ''}<${msg.from.emailAddress.address}>`
      : '';

    const normalized: NormalizedEmailData = {
      messageId:  msg.id ?? `outlook-${mailBox.id}-${folder.id}-${Date.now()}`,
      subject:    msg.subject ?? '',
      fromAddr:   from,
      fromName:   msg.from?.emailAddress?.name ?? null,
      toAddr:     (msg.toRecipients ?? []).map(r => r.emailAddress?.address ?? '').filter(Boolean),
      ccAddr:     (msg.ccRecipients  ?? []).map(r => r.emailAddress?.address ?? '').filter(Boolean),
      bccAddr:    (msg.bccRecipients ?? []).map(r => r.emailAddress?.address ?? '').filter(Boolean),
      bodyText:   msg.body?.contentType === 'text' ? msg.body.content ?? null : msg.bodyPreview ?? null,
      bodyHtml:   msg.body?.contentType === 'html' ? msg.body.content ?? null : null,
      receivedAt: msg.receivedDateTime ? new Date(msg.receivedDateTime) : new Date(),
      isRead:     msg.isRead ?? false,
      isFlagged:  msg.flag?.flagStatus === 'flagged',
      isSpam:     false,
    };

    await this.upsertAndAnalyze(mailBox, folder, normalized);
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

        for (const msg of messages) {
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
          };

          await this.upsertAndAnalyze(
            { id: mailBox.id, userId: mailBox.userId },
            { id: folder.id, type: folder.type },
            normalized,
          );
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
   * upsertAndAnalyze()
   *
   * 1. Upsert email record into DB
   * 2. Collect attachment metadata (already persisted by attachment-storage.service)
   * 3. Call SecurityService.analyze() — full 13-stage pipeline
   * 4. Send NEW_EMAIL_RECEIVED notification if email is new and in INBOX
   */
  private async upsertAndAnalyze(
    mailBox: { id: number; userId: number },
    folder:  { id: number; type: string },
    data:    NormalizedEmailData,
  ): Promise<void> {
    const { id: mailBoxId, userId } = mailBox;
    const folderId  = folder.id;
    const messageId = data.messageId;

    // ── 1. Check if email already exists ──────────────────────────────────────
    const existing = await this.prisma.email.findUnique({
      where: { mailBoxId_folderId_messageId: { mailBoxId, folderId, messageId } },
    });

    if (existing) {
      await this.prisma.email.update({
        where: { id: existing.id },
        data: {
          isRead:    data.isRead,
          isFlagged: data.isFlagged,
        },
      });
      return;
    }
    // ── 2. Upsert email ────────────────────────────────────────────────────────
    const email = await this.prisma.email.upsert({
      where:  { mailBoxId_folderId_messageId: { mailBoxId, folderId, messageId } },
      create: {
        mailBoxId, folderId, messageId,
        subject:   data.subject,
        fromAddr:  data.fromAddr,
        fromName:  data.fromName,
        toAddr:    data.toAddr,
        ccAddr:    data.ccAddr?.length  ? data.ccAddr  : undefined,
        bccAddr:   data.bccAddr?.length ? data.bccAddr : undefined,
        bodyText:  data.bodyText,
        bodyHtml:  data.bodyHtml,
        isRead:    data.isRead,
        isFlagged: data.isFlagged,
        isSpam:    data.isSpam,
        receivedAt: data.receivedAt,
      },
      update: {
        isRead:    data.isRead,
        isFlagged: data.isFlagged,
      },
    });

    // ── 3. Collect attachments (already stored by attachment-storage.service) ──
    const attachments = await this.prisma.attachment.findMany({
      where:  { emailId: email.id },
      select: { storagePath: true, filename: true, mimeType: true, size: true },
    });

    // ── 4. Build SecurityPipelineInput ────────────────────────────────────────
    const pipelineInput: SecurityPipelineInput = {
      emailId:   email.id,
      messageId: data.messageId,
      mailBoxId,
      fromAddr:  data.fromAddr,
      fromName:  data.fromName,
      toAddr:    data.toAddr,
      ccAddr:    data.ccAddr ?? null,
      bccAddr:   data.bccAddr ?? null,
      subject:   data.subject,
      bodyText:  data.bodyText,
      bodyHtml:  data.bodyHtml,
      receivedAt: data.receivedAt,
      attachments: attachments.map(att => ({
        filename:    att.filename  ?? 'unknown',
        mimeType:    att.mimeType  ?? 'application/octet-stream',
        size:        att.size      ?? 0,
        storagePath: att.storagePath,
      })),
    };

    // ── 5. Run full Security Pipeline ────────────────────────────────────────
    // SecurityService handles: detection, scoring, DB update, and threat notifications
    const result = await this.securityService.analyze(pipelineInput, userId);

    this.logger.debug(`Email ${email.id} analyzed: verdict=${result.verdict.label} score=${result.verdict.riskScore} (${result.processingMs}ms)`);

    // ── 6. NEW_EMAIL_RECEIVED notification ────────────────────────────────────
    // Only the processor knows if this is truly a new inbox email
    const isNew = !existing;
    if (isNew && folder.type === FolderType.INBOX) {
      try {
        await this.notificationsService.create({
          userId,
          type:    NotificationType.NEW_EMAIL_RECEIVED,
          title:   'New Email Received',
          message: `New email: ${data.subject || '(No subject)'}`,
          metadata: {
            emailId:  email.id,
            subject:  data.subject,
            fromAddr: data.fromAddr,
            verdict:  result.verdict.label,
            score:    result.verdict.riskScore,
          },
          mailBoxId,
          emailId: email.id,
        });
      } catch { /* Non-fatal */ }
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // STORAGE CHECK
  // ═══════════════════════════════════════════════════════════════════════════

  private async checkLowMailboxSpace(mailBox: { id: number; userId: number }): Promise<void> {
    const limitBytes   = this.configService.get<number>('MAILBOX_STORAGE_LIMIT_BYTES') ?? DEFAULT_STORAGE_LIMIT_BYTES;
    const threshold    = 0.8;

    const result = await this.prisma.attachment.aggregate({
      where: { email: { mailBoxId: mailBox.id } },
      _sum:  { size: true },
    });
    const usedBytes    = result._sum.size ?? 0;
    const usagePercent = usedBytes / limitBytes;

    if (usagePercent >= threshold) {
      try {
        await this.notificationsService.create({
          userId:  mailBox.userId,
          type:    NotificationType.LOW_MAILBOX_SPACE,
          title:   'Low Mailbox Space',
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
