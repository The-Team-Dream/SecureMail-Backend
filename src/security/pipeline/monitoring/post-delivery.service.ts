// ─────────────────────────────────────────────────────────────────────────────
// monitoring/post-delivery.service.ts
//
// Post-Delivery Protection — Stage 11 (final) of the Security Pipeline.
//
// Responsibilities:
//   1. Re-scan stored emails when threat intelligence updates
//   2. Quarantine / remove emails from mailbox folders after new threats found
//   3. Process user phishing reports (feedback loop)
//   4. Generate security digest (weekly summary per user)
//
// Integrates with existing: PrismaService, NotificationsService, FoldersService
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../../prisma.service';
import { NotificationsService } from '../../../notifications/notifications.service';
import { FolderType, NotificationType } from 'generated/prisma/enums';

// ─── Rescan request ───────────────────────────────────────────────────────────
export interface RescanRequest {
  triggerReason: string;       // e.g. 'new_threat_intel' | 'user_report'
  since?:        Date;         // rescan emails received after this date
  ruleIds?:      string[];     // specific rules to re-evaluate
  mailBoxIds?:   number[];     // limit to specific mailboxes
}

// ─── Report result ────────────────────────────────────────────────────────────
export interface PhishingReportResult {
  emailId:     number;
  accepted:    boolean;
  action:      string;
  message:     string;
}

@Injectable()
export class PostDeliveryService {
  private readonly logger = new Logger(PostDeliveryService.name);

  constructor(
    private readonly prisma:         PrismaService,
    private readonly notifications:  NotificationsService,
  ) {}

  // ─── 1. User Phishing Report ───────────────────────────────────────────────
  /**
   * handleUserReport() — process a user-submitted phishing report.
   *
   * Actions:
   *   - Mark email as phishing in DB
   *   - Move to PHISHING folder
   *   - Notify security team (via audit log)
   *   - Return structured result
   */
  async handleUserReport(emailId: number, userId: number): Promise<PhishingReportResult> {
    try {
      const email = await this.prisma.email.findUnique({
        where:   { id: emailId },
        include: { mailBox: { select: { userId: true, id: true } } },
      });

      if (!email) {
        return { emailId, accepted: false, action: 'none', message: 'Email not found' };
      }

      // Authorization check
      if (email.mailBox.userId !== userId) {
        return { emailId, accepted: false, action: 'none', message: 'Unauthorized' };
      }

      // Move to PHISHING folder
      const phishingFolder = await this.getOrCreateFolder(email.mailBoxId, FolderType.PHISHING);

      await this.prisma.email.update({
        where: { id: emailId },
        data:  {
          isPhishing: true,
          folderId:   phishingFolder.id,
        },
      });

      // Send notification to confirm the action
      await this.notifications.create({
        userId,
        type:    NotificationType.PHISHING_DETECTED,
        title:   'Phishing Report Received',
        message: 'Thank you for reporting. The email has been quarantined.',
        metadata: { emailId, reportedBy: userId },
        mailBoxId: email.mailBoxId,
        emailId,
      });

      this.logger.log(`User ${userId} reported email ${emailId} as phishing`);

      return {
        emailId,
        accepted: true,
        action:   'quarantined',
        message:  'Email has been quarantined in your Phishing folder.',
      };

    } catch (err) {
      this.logger.error('handleUserReport failed', { emailId, error: String(err) });
      return { emailId, accepted: false, action: 'none', message: 'Internal error' };
    }
  }

  // ─── 2. Retract / Remove Known-Malicious Email ─────────────────────────────
  /**
   * retractEmail() — move a delivered email to MALWARE/PHISHING folder.
   * Called when threat intel updates identify a previously-safe email as malicious.
   */
  async retractEmail(emailId: number, reason: string): Promise<void> {
    try {
      const email = await this.prisma.email.findUnique({
        where:  { id: emailId },
        select: { id: true, mailBoxId: true, mailBox: { select: { userId: true } } },
      });
      if (!email) return;

      const folder = await this.getOrCreateFolder(email.mailBoxId, FolderType.PHISHING);

      await this.prisma.email.update({
        where: { id: emailId },
        data:  { isPhishing: true, folderId: folder.id },
      });

      await this.notifications.create({
        userId:    email.mailBox.userId,
        type:      NotificationType.PHISHING_DETECTED,
        title:     '🚨 Email Retroactively Flagged',
        message:   `An email you received was identified as a threat: ${reason}`,
        metadata:  { emailId, reason, retracted: true },
        mailBoxId: email.mailBoxId,
        emailId,
      });

      this.logger.log(`Email ${emailId} retracted: ${reason}`);
    } catch (err) {
      this.logger.error('retractEmail failed', { emailId, error: String(err) });
    }
  }

  // ─── 3. Rescan Emails ─────────────────────────────────────────────────────
  /**
   * getEmailsForRescan() — returns emails that should be re-evaluated.
   * The actual re-scanning is delegated to the queue (email-sync processor)
   * to avoid blocking the HTTP request.
   */
  async getEmailsForRescan(request: RescanRequest): Promise<number[]> {
    const since = request.since ?? new Date(Date.now() - 7 * 24 * 60 * 60 * 1000); // default: last 7 days

    const whereClause: Record<string, unknown> = {
      receivedAt: { gte: since },
      isPhishing: false,
      isSpam:     false,
    };

    if (request.mailBoxIds && request.mailBoxIds.length > 0) {
      whereClause.mailBoxId = { in: request.mailBoxIds };
    }

    const emails = await this.prisma.email.findMany({
      where:  whereClause,
      select: { id: true },
      take:   500, // safety limit
    });

    this.logger.log(
      `Rescan triggered: ${emails.length} emails queued. ` +
      `Reason: ${request.triggerReason}`,
    );

    return emails.map(e => e.id);
  }

  // ─── 4. Weekly Security Digest ────────────────────────────────────────────
  /**
   * generateWeeklyDigest() — creates a weekly security summary notification.
   * Called by the scheduler (refresh-tokens.job.ts or a new weekly job).
   */
  async generateWeeklyDigest(userId: number): Promise<void> {
    try {
      const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

      const mailBoxes = await this.prisma.mailBox.findMany({
        where:  { userId },
        select: { id: true },
      });
      const mailBoxIds = mailBoxes.map(m => m.id);

      const [spamCount, phishingCount, malwareCount, totalCount] = await Promise.all([
        this.prisma.email.count({ where: { mailBoxId: { in: mailBoxIds }, isSpam: true,     receivedAt: { gte: since } } }),
        this.prisma.email.count({ where: { mailBoxId: { in: mailBoxIds }, isPhishing: true, receivedAt: { gte: since } } }),
        this.prisma.email.count({ where: { mailBoxId: { in: mailBoxIds }, malwareVerdict: 'malicious', receivedAt: { gte: since } } }),
        this.prisma.email.count({ where: { mailBoxId: { in: mailBoxIds }, receivedAt: { gte: since } } }),
      ]);

      if (totalCount === 0) return; // No activity — skip notification

      const message =
        `Weekly security report: ${totalCount} emails received. ` +
        `${phishingCount} phishing, ${spamCount} spam, ${malwareCount} malware threats blocked.`;

      await this.notifications.create({
        userId,
        type:     NotificationType.WEEKLY_SECURITY_REPORT,
        title:    '📊 Weekly Security Digest',
        message,
        metadata: { spamCount, phishingCount, malwareCount, totalCount, since: since.toISOString() },
      });

    } catch (err) {
      this.logger.error('generateWeeklyDigest failed', { userId, error: String(err) });
    }
  }

  // ─── Helper ──────────────────────────────────────────────────────────────
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
