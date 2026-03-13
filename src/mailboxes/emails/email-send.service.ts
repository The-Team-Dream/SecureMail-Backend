// ─────────────────────────────────────────────────────────────────────────────
// mailboxes/emails/email-send.service.ts
//
// UPDATED: attachmentPaths now uses StoredAttachment (url + publicId)
// instead of the old { path } disk-based shape.
//
// Key change:
//   Old: { path: '/uploads/attachments/...', filename, mimeType }
//   New: { url: 'https://res.cloudinary.com/...', publicId: 'securemail/...', filename, mimeType }
//
// The 'url' is what gets stored in the DB and passed to the send processor.
// The 'publicId' is what gets used for cleanup (Cloudinary deletion).
// ─────────────────────────────────────────────────────────────────────────────

import {
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { PrismaService } from '../../prisma.service';
import { MailboxesService } from '../mailboxes.service';
import { AttachmentStorageService, StoredAttachment } from './attachment-storage.service';
import { SendEmailDto } from './dto/send-email.dto';

export const EMAIL_SEND_QUEUE = 'email-send';

// ── Updated job data shape — uses Cloudinary StoredAttachment ─────────────────
export interface SendJobData {
  userId:           number;
  mailboxId:        number;
  type:             'send' | 'reply' | 'forward';
  to:               string;
  cc?:              string[];
  bcc?:             string[];
  subject:          string;
  bodyText?:        string;
  bodyHtml?:        string;
  inReplyTo?:       string;
  references?:      string;
  replyToEmailId?:  number;
  forwardEmailId?:  number;
  // Updated: url (Cloudinary CDN) instead of path (local disk)
  attachments?:     Array<{ url: string; publicId: string; filename: string; mimeType: string }>;
}

@Injectable()
export class EmailSendService {
  constructor(
    private prisma:             PrismaService,
    private mailboxesService:   MailboxesService,
    private attachmentStorage:  AttachmentStorageService,
    @InjectQueue(EMAIL_SEND_QUEUE) private sendQueue: Queue,
  ) {}

  // ── Upload files to Cloudinary and return StoredAttachment array ─────────────
  async prepareAttachments(
    files: Express.Multer.File[],
  ): Promise<StoredAttachment[]> {
    if (!files?.length) return [];
    return this.attachmentStorage.saveAttachments(files);
  }

  // ── Delete uploaded attachments from Cloudinary (called on send failure) ─────
  async cleanupAttachments(attachments: StoredAttachment[]): Promise<void> {
    if (!attachments?.length) return;
    await this.attachmentStorage.cleanupAttachments(
      attachments.map(a => ({ publicId: a.publicId })),
    );
  }

  async queueSend(
    userId:      number,
    mailboxId:   number,
    dto:         SendEmailDto,
    attachments: StoredAttachment[],
  ) {
    await this.mailboxesService.findOne(userId, mailboxId);

    const jobData: SendJobData = {
      userId,
      mailboxId,
      type:     'send',
      to:       dto.to,
      cc:       dto.cc,
      bcc:      dto.bcc,
      subject:  dto.subject,
      bodyText: dto.bodyText,
      bodyHtml: dto.bodyHtml,
      attachments: attachments.length ? attachments : undefined,
    };

    await this.sendQueue.add('send-email', jobData, {
      attempts: 3,
      backoff:  { type: 'exponential', delay: 5000 },
    });

    return { message: 'Email queued for sending', status: 'queued' };
  }

  async queueReply(
    userId:      number,
    mailboxId:   number,
    emailId:     number,
    content:     string,
    bodyHtml:    string | undefined,
    attachments: StoredAttachment[],
  ) {
    const email = await this.prisma.email.findFirst({
      where: { id: emailId, mailBoxId: mailboxId },
    });
    if (!email) throw new NotFoundException('Email not found');

    const mailbox = await this.prisma.mailBox.findFirst({
      where: { id: mailboxId, userId },
    });
    if (!mailbox) throw new NotFoundException('Mailbox not found');

    const fromAddr = typeof email.fromAddr === 'string' ? email.fromAddr : '';
    const toMatch  = fromAddr.match(/<([^>]+)>/);
    const replyTo  = toMatch ? toMatch[1] : fromAddr;

    const subject       = email.subject.startsWith('Re:') ? email.subject : `Re: ${email.subject}`;
    const bodyText      = bodyHtml ? undefined : content;
    const bodyHtmlFinal = bodyHtml ?? `<p>${content.replace(/\n/g, '</p><p>')}</p>`;

    const jobData: SendJobData = {
      userId,
      mailboxId,
      type:          'reply',
      to:            replyTo,
      subject,
      bodyText,
      bodyHtml:      bodyHtmlFinal,
      inReplyTo:     email.messageId,
      references:    (email as { references?: string }).references ?? email.messageId,
      replyToEmailId: emailId,
      attachments:   attachments.length ? attachments : undefined,
    };

    await this.sendQueue.add('send-email', jobData, {
      attempts: 3,
      backoff:  { type: 'exponential', delay: 5000 },
    });

    return { message: 'Reply queued for sending', status: 'queued' };
  }

  async queueForward(
    userId:      number,
    mailboxId:   number,
    emailId:     number,
    to:          string,
    message:     string | undefined,
    attachments: StoredAttachment[],
  ) {
    const email = await this.prisma.email.findFirst({
      where:   { id: emailId, mailBoxId: mailboxId },
      include: { attachments: true },
    });
    if (!email) throw new NotFoundException('Email not found');

    const mailbox = await this.prisma.mailBox.findFirst({
      where: { id: mailboxId, userId },
    });
    if (!mailbox) throw new NotFoundException('Mailbox not found');

    const subject          = email.subject.startsWith('Fwd:') ? email.subject : `Fwd: ${email.subject}`;
    const forwardedContent = this.buildForwardedContent(email, message);

    const jobData: SendJobData = {
      userId,
      mailboxId,
      type:           'forward',
      to,
      subject,
      bodyText:       forwardedContent,
      bodyHtml:       `<pre>${forwardedContent.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>`,
      forwardEmailId: emailId,
      attachments:    attachments.length ? attachments : undefined,
    };

    await this.sendQueue.add('send-email', jobData, {
      attempts: 3,
      backoff:  { type: 'exponential', delay: 5000 },
    });

    return { message: 'Forward queued for sending', status: 'queued' };
  }

  private buildForwardedContent(
    email: { fromAddr: string; toAddr: unknown; subject: string; receivedAt: Date; bodyText?: string | null },
    message?: string,
  ): string {
    const toStr = Array.isArray(email.toAddr) ? email.toAddr.join(', ') : String(email.toAddr);
    let content = '';
    if (message) content += message + '\n\n';
    content += '---------- Forwarded message ---------\n';
    content += `From: ${email.fromAddr}\n`;
    content += `Date: ${email.receivedAt.toISOString()}\n`;
    content += `Subject: ${email.subject}\n`;
    content += `To: ${toStr}\n\n`;
    content += email.bodyText ?? '(No content)';
    return content;
  }
}
