import {
  BadRequestException,
  Injectable,
  NotFoundException,
  StreamableFile,
  Logger,
} from '@nestjs/common';
import { PrismaService } from '../../prisma.service';
import { FolderType } from '@prisma/client';
import { ReportType } from './dto/report-email.dto';
import { TargetFolderType } from './dto/reclassify-email.dto';

import { MailboxesService } from '../mailboxes.service';
import { forwardRef, Inject } from '@nestjs/common';
import { SecurityService } from '../../security/security.service';
import { SecurityPipelineInput } from '../../security/security.service';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';

@Injectable()
export class EmailsService {
  private readonly logger = new Logger(EmailsService.name);

  constructor(
    private prisma: PrismaService,
    @Inject(forwardRef(() => MailboxesService))
    private mailboxesService: MailboxesService,
    private securityService: SecurityService,
    @InjectQueue('email-process') private readonly processQueue: Queue,
  ) {}

  async ensureMailboxAccess(userId: number, mailboxId: number) {
    const mailbox = await this.prisma.mailBox.findFirst({
      where: { id: mailboxId, userId },
    });
    if (!mailbox) {
      throw new NotFoundException('Mailbox not found');
    }
    return mailbox;
  }



  async listByFolder(
    userId: number,
    mailboxId: number,
    folderType: FolderType,
    page: number,
    limit: number,
  ) {
    await this.ensureMailboxAccess(userId, mailboxId);
    const folder = await this.getOrCreateFolder(mailboxId, folderType);

    const skip = (page - 1) * limit;
    const [emails, total] = await Promise.all([
      this.prisma.email.findMany({
        where: { mailBoxId: mailboxId, folderId: folder.id },
        orderBy: { receivedAt: 'desc' },
        skip,
        take: limit,
        select: {
          id: true,
          mailBoxId: true,
          subject: true,
          fromAddr: true,
          fromName: true,
          toAddr: true,
          isRead: true,
          isFlagged: true,
          isSpam: true,
          isPhishing: true,
          receivedAt: true,
          spamScore: true,
          phishingScore: true,
          malwareVerdict: true,
          malwareScore: true,
          malwareSeverity: true,
          attachments: {
            select: {
              id: true,
              filename: true,
              size: true,
            },
          },
        },
      }),
      this.prisma.email.count({
        where: { mailBoxId: mailboxId, folderId: folder.id },
      }),
    ]);

    return {
      data: emails,
      meta: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  async listStarred(
    userId: number,
    mailboxId: number,
    page: number,
    limit: number,
  ) {
    await this.ensureMailboxAccess(userId, mailboxId);

    const skip = (page - 1) * limit;
    const [emails, total] = await Promise.all([
      this.prisma.email.findMany({
        where: { mailBoxId: mailboxId, isFlagged: true },
        orderBy: { receivedAt: 'desc' },
        skip,
        take: limit,
        select: {
          id: true,
          mailBoxId: true,
          subject: true,
          fromAddr: true,
          fromName: true,
          toAddr: true,
          isRead: true,
          isFlagged: true,
          isSpam: true,
          isPhishing: true,
          receivedAt: true,
          spamScore: true,
          phishingScore: true,
          malwareVerdict: true,
          malwareScore: true,
          malwareSeverity: true,
          attachments: {
            select: {
              id: true,
              filename: true,
              size: true,
            },
          },
          folder: { select: { id: true, type: true } },
        },
      }),
      this.prisma.email.count({
        where: { mailBoxId: mailboxId, isFlagged: true },
      }),
    ]);

    return {
      data: emails,
      meta: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  async search(
    userId: number,
    mailboxId: number,
    q: string | undefined,
    page: number,
    limit: number,
  ) {
    await this.ensureMailboxAccess(userId, mailboxId);

    const skip = (page - 1) * limit;
    
    // If no query provided, just return all emails in mailbox
    const whereClause: any = { mailBoxId: mailboxId };
    
    if (q && q.trim().length > 0) {
      const searchStr = q.trim();
      whereClause.OR = [
        { subject: { contains: searchStr, mode: 'insensitive' } },
        { fromAddr: { contains: searchStr, mode: 'insensitive' } },
        { fromName: { contains: searchStr, mode: 'insensitive' } },
      ];
    }

    const [emails, total] = await Promise.all([
      this.prisma.email.findMany({
        where: whereClause,
        orderBy: { receivedAt: 'desc' },
        skip,
        take: limit,
        select: {
          id: true,
          mailBoxId: true,
          subject: true,
          fromAddr: true,
          fromName: true,
          toAddr: true,
          isRead: true,
          isFlagged: true,
          isSpam: true,
          isPhishing: true,
          receivedAt: true,
          spamScore: true,
          phishingScore: true,
          malwareVerdict: true,
          malwareScore: true,
          malwareSeverity: true,
          attachments: {
            select: {
              id: true,
              filename: true,
              size: true,
            },
          },
          folder: { select: { id: true, type: true } },
        },
      }),
      this.prisma.email.count({
        where: whereClause,
      }),
    ]);

    return {
      data: emails,
      meta: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  async findOne(userId: number, mailboxId: number, emailId: number) {
    await this.ensureMailboxAccess(userId, mailboxId);
    const email = await this.prisma.email.findFirst({
      where: { id: emailId, mailBoxId: mailboxId },
      include: {
        attachments: true,
        folder: { select: { id: true, name: true, type: true } },
      },
    });
    if (!email) {
      throw new NotFoundException('Email not found');
    }

    const securityReport = this.mapAiReportToSecurityModel(email);

    // If the email is stuck in PENDING for more than 4 minutes, return it as FAILED
    // so the UI stops showing "Scanning..." indefinitely and enables the Scan button.
    let analysisStatus = email.analysisStatus;
    const STUCK_THRESHOLD_MS = 4 * 60 * 1000; // 4 minutes
    if (
      analysisStatus === 'PENDING' &&
      Date.now() - new Date(email.createdAt).getTime() > STUCK_THRESHOLD_MS
    ) {
      analysisStatus = 'FAILED';
    }

    // Dynamically check BullMQ processQueue to see if this email is currently undergoing a live rescan
    const activeJobs = await this.processQueue.getActive();
    const waitingJobs = await this.processQueue.getJobs(['wait', 'paused']);
    const isRescanning = [...activeJobs, ...waitingJobs].some(
      (j) => j.data?.emailId === email.id
    );

    return {
      ...email,
      analysisStatus,
      aiReportStatus: email.aiReport ? 'COMPLETED' : 'PENDING',
      securityReport,
      isRescanning,
    };
  }

  private mapAiReportToSecurityModel(email: any) {
    if (!email.aiReport) return null;

    const report = email.aiReport as any;

    // Derive status from BACKEND classification (the source of truth),
    // not from the AI's verdict (which uses a different scale: SAFE/SUSPICIOUS/DANGEROUS).
    // This ensures the banner accurately reflects where the rule engine placed the email.
    let status: string;
    if (email.malwareVerdict && email.malwareVerdict !== 'clean') {
      status = 'MALICIOUS';
    } else if (email.isPhishing) {
      status = 'PHISHING';
    } else if (email.isSpam) {
      status = 'SPAM';
    } else {
      // Not classified as a threat by the backend — use AI verdict for SUSPICIOUS/SAFE distinction
      // Map AI scale (SAFE/SUSPICIOUS/DANGEROUS) to backend scale
      const aiVerdict = (report.verdict || 'SAFE') as string;
      if (aiVerdict === 'DANGEROUS') status = 'SUSPICIOUS'; // Downgraded: backend didn't confirm threat
      else if (aiVerdict === 'SUSPICIOUS') status = 'SUSPICIOUS';
      else status = 'SAFE';
    }

    return {
      status,
      confidenceScore: report.confidence || 0,
      detectionMessage: report.summary || 'Security analysis complete.',
      severity: report.severity || 'LOW',
      priority: report.priority || 'NORMAL',
      reason: report.explanation || 'No specific threat detected.',
      description: report.explanation || '',
      recommendationTitle: 'Security Recommendation',
      recommendationText: report.recommendation || 'No specific actions required.',
      suggestedActions: report.replySuggestions || [],
      anomalies: report.behavioralAnomaly
        ? [
            {
              type: 'BEHAVIORAL',
              title: 'Anomaly Detected',
              description: report.anomalyDescription || 'Suspicious behavior pattern found.',
            },
          ]
        : [],
      emailId: email.id.toString(),
      analysisEngine: 'SecureMail AI-Guard',
    };
  }

  async markRead(
    userId: number,
    mailboxId: number,
    emailId: number,
    read: boolean,
  ) {
    await this.ensureMailboxAccess(userId, mailboxId);
    const email = await this.prisma.email.findFirst({
      where: { id: emailId, mailBoxId: mailboxId },
      include: { folder: true },
    });
    if (!email) {
      throw new NotFoundException('Email not found');
    }
    await this.prisma.email.update({
      where: { id: emailId },
      data: { isRead: read },
    });

    // Synchronize with remote provider
    if (email.messageId && email.folder?.remoteId) {
       await this.mailboxesService.markRemoteRead(
         mailboxId, 
         email.messageId, 
         read, 
         email.folder.remoteId
       );
    }

    return this.findOne(userId, mailboxId, emailId);
  }

  async toggleStar(
    userId: number,
    mailboxId: number,
    emailId: number,
    starred: boolean,
  ) {
    await this.ensureMailboxAccess(userId, mailboxId);
    const email = await this.prisma.email.findFirst({
      where: { id: emailId, mailBoxId: mailboxId },
    });
    if (!email) {
      throw new NotFoundException('Email not found');
    }
    await this.prisma.email.update({
      where: { id: emailId },
      data: { isFlagged: starred },
    });

    return this.findOne(userId, mailboxId, emailId);
  }

  async delete(userId: number, mailboxId: number, emailId: number) {
    await this.ensureMailboxAccess(userId, mailboxId);
    const email = await this.prisma.email.findFirst({
      where: { id: emailId, mailBoxId: mailboxId },
      include: { folder: true },
    });
    if (!email) {
      throw new NotFoundException('Email not found');
    }

    const trashFolder = await this.prisma.folder.findFirst({
      where: { mailBoxId: mailboxId, type: FolderType.TRASH },
    });

    if (trashFolder) {
      await this.prisma.email.update({
        where: { id: emailId },
        data: { folderId: trashFolder.id },
      });
    } else {
      await this.prisma.email.delete({ where: { id: emailId } });
    }

    // Synchronize with remote provider
    if (email.messageId && email.folder?.remoteId) {
      await this.mailboxesService.deleteRemoteEmail(
        mailboxId,
        email.messageId,
        email.folder.remoteId
      );
    }

    return trashFolder
      ? { message: 'Email moved to trash', action: 'trashed' as const, emailId }
      : { message: 'Email deleted', action: 'deleted' as const, emailId };
  }

  async report( 
    userId: number,
    mailboxId: number,
    emailId: number,
    type: ReportType,
  ) {
    await this.ensureMailboxAccess(userId, mailboxId);
    const email = await this.prisma.email.findFirst({
      where: { id: emailId, mailBoxId: mailboxId },
      include: { folder: true },
    });
    if (!email) {
      throw new NotFoundException('Email not found');
    }

    if (type === ReportType.SPAM) {
      const spamFolder = await this.getOrCreateFolder(mailboxId, FolderType.SPAM);
      await this.prisma.email.update({
        where: { id: emailId },
        data: {
          folderId: spamFolder.id,
          isSpam: true,
          spamScore: 100,
        },
      });
    } else if (type === ReportType.PHISHING) {
      const phishingFolder = await this.getOrCreateFolder(
        mailboxId,
        FolderType.PHISHING,
      );
      await this.prisma.email.update({
        where: { id: emailId },
        data: {
          folderId: phishingFolder.id,
          isPhishing: true,
          phishingScore: 100,
        },
      });
    }

    return this.findOne(userId, mailboxId, emailId);
  }

  async reclassify(
    userId: number,
    mailboxId: number,
    emailId: number,
    targetFolder: TargetFolderType,
  ) {
    await this.ensureMailboxAccess(userId, mailboxId);
    const email = await this.prisma.email.findFirst({
      where: { id: emailId, mailBoxId: mailboxId },
    });
    if (!email) {
      throw new NotFoundException('Email not found');
    }

    const folderTypeMap: Record<TargetFolderType, FolderType> = {
      [TargetFolderType.INBOX]: FolderType.INBOX,
      [TargetFolderType.SENT]: FolderType.SENT,
      [TargetFolderType.SPAM]: FolderType.SPAM,
      [TargetFolderType.PHISHING]: FolderType.PHISHING,
      [TargetFolderType.TRASH]: FolderType.TRASH,
    };

    const folderType = folderTypeMap[targetFolder];
    const folder = await this.getOrCreateFolder(mailboxId, folderType);

    const updateData: { folderId: number; isSpam?: boolean; isPhishing?: boolean } = {
      folderId: folder.id,
    };
    if (folderType === FolderType.SPAM) updateData.isSpam = true;
    else if (folderType === FolderType.PHISHING) updateData.isPhishing = true;
    else {
      updateData.isSpam = false;
      updateData.isPhishing = false;
    }

    await this.prisma.email.update({
      where: { id: emailId },
      data: updateData,
    });

    return this.findOne(userId, mailboxId, emailId);
  }

  private async getOrCreateFolder(
    mailboxId: number,
    type: FolderType,
  ) {
    let folder = await this.prisma.folder.findFirst({
      where: { mailBoxId: mailboxId, type },
    });
    if (!folder) {
      folder = await this.prisma.folder.create({
        data: {
          mailBoxId: mailboxId,
          name: type.toLowerCase(),
          type,
          remoteId: type,
        },
      });
    }
    return folder;
  }

  async downloadAttachment(
    userId: number,
    mailboxId: number,
    emailId: number,
    attachmentId: number,
  ) {
    await this.ensureMailboxAccess(userId, mailboxId);
    
    const attachment = await this.prisma.attachment.findFirst({
      where: { 
        id: attachmentId, 
        emailId: emailId,
        email: { mailBoxId: mailboxId }
      },
      include: { email: { select: { analysisStatus: true } } },
    });

    if (!attachment) {
      throw new NotFoundException('Attachment not found');
    }

    if (attachment.email.analysisStatus === 'PENDING') {
      throw new BadRequestException('Cannot download attachment while email is still undergoing security analysis');
    }

    // If it's a Cloudinary URL or remote URL, return redirect directive
    if (attachment.storagePath.startsWith('http://') || attachment.storagePath.startsWith('https://')) {
      return { url: attachment.storagePath, type: 'redirect' };
    }

    // Since we've migrated to Cloudinary, local file streaming is deprecated.
    // If we reach here, it means storagePath was not a URL, which shouldn't happen for new records.
    throw new NotFoundException('Attachment source not available (deprecated local storage)');
  }
  async listReports(
    userId: number,
    mailboxId: number,
    page: number,
    limit: number,
  ) {
    await this.ensureMailboxAccess(userId, mailboxId);

    const skip = (page - 1) * limit;

    // Define what constitutes a security incident for the report list
    const whereClause = {
      mailBoxId: mailboxId,
      OR: [
        { isSpam: true },
        { isPhishing: true },
        { NOT: { malwareVerdict: null } },
        { analysisStatus: 'PENDING' as const },
      ],
    };

    const [emails, total, criticalCount, pendingCount, resolvedCount] = await Promise.all([
      this.prisma.email.findMany({
        where: whereClause,
        orderBy: { receivedAt: 'desc' },
        skip,
        take: limit,
        select: {
          id: true,
          subject: true,
          fromAddr: true,
          fromName: true,
          isRead: true,
          receivedAt: true,
          isSpam: true,
          isPhishing: true,
          phishingScore: true,
          malwareVerdict: true,
          malwareSeverity: true,
          analysisStatus: true,
        },
      }),
      this.prisma.email.count({ where: whereClause }),
      // Stats
      this.prisma.email.count({
        where: {
          mailBoxId: mailboxId,
          OR: [
            { NOT: { malwareVerdict: null } },
            { isPhishing: true, phishingScore: { gt: 80 } },
          ],
        },
      }),
      this.prisma.email.count({
        where: { mailBoxId: mailboxId, analysisStatus: 'PENDING' },
      }),
      this.prisma.email.count({
        where: {
          mailBoxId: mailboxId,
          analysisStatus: 'COMPLETED',
          isSpam: false,
          isPhishing: false,
          malwareVerdict: null,
        },
      }),
    ]);

    // Map to Incident Model expected by Flutter
    const data = emails.map((email) => {
      let type = 'suspiciousActivity';
      let title = email.subject || 'No Subject';
      const description = `From: ${email.fromAddr}`;

      if (email.malwareVerdict || (email.isPhishing && email.phishingScore > 80)) {
        type = 'criticalThreat';
      } else if (email.analysisStatus === 'PENDING') {
        type = 'systemUpdate'; // Using this as placeholder for "Analysis in progress" in UI
      }

      return {
        id: email.id.toString(),
        type,
        title,
        description,
        timeAgo: email.receivedAt.toISOString(), // Frontend will format this
        isRead: email.isRead,
      };
    });

    return {
      data,
      meta: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
        stats: {
          critical: criticalCount,
          pending: pendingCount,
          resolved: resolvedCount,
        },
      },
    };
  }

  async scanEmail(userId: number, mailboxId: number, emailId: number) {
    await this.ensureMailboxAccess(userId, mailboxId);
    const email = await this.prisma.email.findFirst({
      where: { id: emailId, mailBoxId: mailboxId },
      include: { attachments: true },
    });
    if (!email) {
      throw new NotFoundException('Email not found');
    }

    const STUCK_THRESHOLD_MS = 4 * 60 * 1000; // 4 minutes
    const isStuck =
      email.analysisStatus === 'PENDING' &&
      Date.now() - new Date(email.createdAt).getTime() > STUCK_THRESHOLD_MS;

    if (email.analysisStatus === 'PENDING' && !isStuck) {
      return {
        message: 'Scan already in progress',
        emailId,
      };
    }

    // If the email already has a completed AI report, keep analysisStatus as COMPLETED
    // so the existing report remains visible during the rescan. Otherwise, set to PENDING.
    const newStatus = email.aiReport ? 'COMPLETED' : 'PENDING';

    await this.prisma.email.update({
      where: { id: email.id },
      data: {
        analysisStatus: newStatus,
        createdAt: new Date(),
      },
    });

    // Enqueue background job to prevent overloading the AI model
    await this.processQueue.add('process-email', {
      emailId: email.id,
      mailBoxId: mailboxId,
      userId: userId,
      messageId: email.messageId || '',
    }, { jobId: `process-${email.id}`, removeOnComplete: 1000, removeOnFail: 5000 });

    return {
      message: 'Scan enqueued',
      emailId,
    };
  }

  async scanAllEmails(userId: number, mailboxId: number) {
    await this.ensureMailboxAccess(userId, mailboxId);

    // Get ALL emails so we can force a re-scan with the AI model.
    const emails = await this.prisma.email.findMany({
      where: { mailBoxId: mailboxId },
      select: { id: true, messageId: true, aiReport: true },
    });

    if (emails.length === 0) {
      return { message: 'Mailbox is empty', results: [] };
    }

    // Set emails WITHOUT aiReport to PENDING. Emails WITH aiReport keep their COMPLETED status.
    const emailsWithoutReport = emails.filter(e => !e.aiReport);
    if (emailsWithoutReport.length > 0) {
      await this.prisma.email.updateMany({
        where: { id: { in: emailsWithoutReport.map(e => e.id) } },
        data: { analysisStatus: 'PENDING' },
      });
    }

    // Enqueue background jobs for each email
    const jobs = emails.map(email => ({
      name: 'process-email',
      data: {
        emailId: email.id,
        mailBoxId: mailboxId,
        userId: userId,
        messageId: email.messageId,
      },
      opts: { jobId: `process-${email.id}`, removeOnComplete: 1000, removeOnFail: 5000 },
    }));

    await this.processQueue.addBulk(jobs);

    return {
      message: `Background scanning started for ${emails.length} emails.`,
      totalEnqueued: emails.length,
    };
  }

  async getScanProgress(userId: number, mailboxId: number) {
    await this.ensureMailboxAccess(userId, mailboxId);

    const total = await this.prisma.email.count({
      where: { mailBoxId: mailboxId },
    });

    const pending = await this.prisma.email.count({
      where: { mailBoxId: mailboxId, analysisStatus: 'PENDING' },
    });

    const completed = total - pending;
    const percentage = total === 0 ? 100 : Math.round((completed / total) * 100);

    return {
      total,
      completed,
      pending,
      percentage,
      isScanning: pending > 0,
    };
  }

  async getQueueStatus(userId: number, mailboxId: number) {
    await this.ensureMailboxAccess(userId, mailboxId);

    // Fetch active, waiting, and paused jobs from BullMQ processQueue
    const activeJobs = await this.processQueue.getActive();
    const waitingJobs = await this.processQueue.getJobs(['wait', 'paused']);

    const isPaused = await this.processQueue.isPaused();

    // Map jobs to friendly details, filtering by current mailboxId to only show relevant ones
    const active = activeJobs
      .filter((j) => j.data?.mailBoxId === mailboxId)
      .map((j) => ({
        jobId: j.id,
        emailId: j.data?.emailId,
        messageId: j.data?.messageId,
        addedAt: j.timestamp ? new Date(j.timestamp) : new Date(),
        progress: j.progress,
      }));

    const waiting = waitingJobs
      .filter((j) => j.data?.mailBoxId === mailboxId)
      .map((j) => ({
        jobId: j.id,
        emailId: j.data?.emailId,
        messageId: j.data?.messageId,
        addedAt: j.timestamp ? new Date(j.timestamp) : new Date(),
      }));

    return {
      active,
      waiting,
      activeCount: active.length,
      waitingCount: waiting.length,
      isPaused,
    };
  }

  async controlQueue(userId: number, mailboxId: number, action: 'pause' | 'resume' | 'clear') {
    await this.ensureMailboxAccess(userId, mailboxId);

    if (action === 'pause') {
      // Queue.pause() in BullMQ only writes a flag to Redis (fast). It does NOT block waiting for active jobs.
      // We must await it so the paused state is committed before we return the response,
      // otherwise the frontend refetches and sees isPaused=false, hides the Resume button forever.
      await this.processQueue.pause();
      return { message: 'Queue paused successfully' };
    } else if (action === 'resume') {
      await this.processQueue.resume();
      return { message: 'Queue resumed successfully' };
    } else if (action === 'clear') {
      // Clear waiting, paused, and delayed jobs (up to 10,000 jobs to avoid blocking Redis)
      await this.processQueue.clean(0, 10000, 'wait');
      await this.processQueue.clean(0, 10000, 'paused');
      await this.processQueue.clean(0, 10000, 'delayed');
      
      // Update database status of waiting/pending emails for this mailbox back to 'FAILED' so they don't get stuck!
      await this.prisma.email.updateMany({
        where: { mailBoxId: mailboxId, analysisStatus: 'PENDING' },
        data: { analysisStatus: 'FAILED' },
      });

      return { message: 'Queue cleared successfully' };
    }

    throw new BadRequestException('Invalid queue control action');
  }

  async cancelScanJob(userId: number, mailboxId: number, emailId: number) {
    await this.ensureMailboxAccess(userId, mailboxId);

    const job = await this.processQueue.getJob(`process-${emailId}`);
    if (job) {
      try {
        // Remove job from Redis
        await job.remove();
      } catch (err) {
        // If removing fails (e.g., job is active and locked), try to discard it first
        try {
          await job.discard();
          await job.remove();
        } catch (innerErr) {
          this.logger.warn(`Could not forcefully remove active scan job process-${emailId}: ${innerErr.message}`);
        }
      }
    }

    // Reset status in database
    await this.prisma.email.update({
      where: { id: emailId },
      data: { analysisStatus: 'FAILED' },
    });

    return { message: 'Scan cancelled successfully', emailId };
  }
}
