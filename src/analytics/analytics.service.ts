import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { FolderType } from '@prisma/client';

@Injectable()
export class AnalyticsService {
  constructor(private readonly prisma: PrismaService) {}

  private async ensureMailboxAccess(userId: number, mailboxId: number) {
    const mailbox = await this.prisma.mailBox.findFirst({
      where: { id: mailboxId, userId },
    });
    if (!mailbox) {
      throw new NotFoundException('Mailbox not found');
    }
    return mailbox;
  }

  async getOverview(userId: number) {
    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    const sixtyDaysAgo = new Date(now.getTime() - 60 * 24 * 60 * 60 * 1000);

    const [
      mailboxCount,
      totalEmails,
      phishingCount,
      spamCount,
      malwareCount,
      storageUsed,
      currentPhishing,
      prevPhishing,
      currentSpam,
      prevSpam,
      currentMalware,
      prevMalware,
    ] = await Promise.all([
      this.prisma.mailBox.count({ where: { userId, isActive: true } }),
      this.prisma.email.count({
        where: { mailBox: { userId } },
      }),
      this.prisma.email.count({
        where: { mailBox: { userId }, isPhishing: true },
      }),
      this.prisma.email.count({
        where: { mailBox: { userId }, isSpam: true },
      }),
      this.prisma.email.count({
        where: { mailBox: { userId }, malwareVerdict: 'malicious' },
      }),
      this.prisma.attachment.aggregate({
        where: {
          email: { mailBox: { userId } },
        },
        _sum: { size: true },
      }),
      // Trends calculation
      this.prisma.email.count({
        where: { mailBox: { userId }, isPhishing: true, receivedAt: { gte: thirtyDaysAgo } },
      }),
      this.prisma.email.count({
        where: { mailBox: { userId }, isPhishing: true, receivedAt: { gte: sixtyDaysAgo, lt: thirtyDaysAgo } },
      }),
      this.prisma.email.count({
        where: { mailBox: { userId }, isSpam: true, receivedAt: { gte: thirtyDaysAgo } },
      }),
      this.prisma.email.count({
        where: { mailBox: { userId }, isSpam: true, receivedAt: { gte: sixtyDaysAgo, lt: thirtyDaysAgo } },
      }),
      this.prisma.email.count({
        where: { mailBox: { userId }, malwareVerdict: 'malicious', receivedAt: { gte: thirtyDaysAgo } },
      }),
      this.prisma.email.count({
        where: { mailBox: { userId }, malwareVerdict: 'malicious', receivedAt: { gte: sixtyDaysAgo, lt: thirtyDaysAgo } },
      }),
    ]);

    const calculateChange = (current: number, prev: number) => {
      if (prev === 0) return current > 0 ? '+100%' : '0%';
      const diff = ((current - prev) / prev) * 100;
      return (diff >= 0 ? '+' : '') + diff.toFixed(0) + '%';
    };

    return {
      totalMailboxesConnected: mailboxCount,
      totalEmails: totalEmails,
      totalPhishingDetected: phishingCount,
      totalSpamDetected: spamCount,
      totalMalwareDetected: malwareCount,
      totalStorageUsed: storageUsed._sum.size ?? 0,
      threatsChange: calculateChange(currentPhishing + currentSpam + currentMalware, prevPhishing + prevSpam + prevMalware),
      phishingChange: calculateChange(currentPhishing + currentMalware, prevPhishing + prevMalware),
    };
  }

  async getMailboxStats(userId: number, mailboxId: number) {
    await this.ensureMailboxAccess(userId, mailboxId);

    const inboxFolder = await this.prisma.folder.findFirst({
      where: { mailBoxId: mailboxId, type: FolderType.INBOX },
    });
    const sentFolder = await this.prisma.folder.findFirst({
      where: { mailBoxId: mailboxId, type: FolderType.SENT },
    });

    const [
      totalEmails,
      unreadCount,
      sentCount,
      spamCount,
      phishingCount,
      storageUsed,
      mailbox,
    ] = await Promise.all([
      this.prisma.email.count({ where: { mailBoxId: mailboxId } }),
      this.prisma.email.count({
        where: { mailBoxId: mailboxId, isRead: false },
      }),
      sentFolder
        ? this.prisma.email.count({
            where: { mailBoxId: mailboxId, folderId: sentFolder.id },
          })
        : 0,
      this.prisma.email.count({
        where: { mailBoxId: mailboxId, isSpam: true },
      }),
      this.prisma.email.count({
        where: { mailBoxId: mailboxId, isPhishing: true },
      }),
      this.prisma.attachment.aggregate({
        where: { email: { mailBoxId: mailboxId } },
        _sum: { size: true },
      }),
      this.prisma.mailBox.findUnique({
        where: { id: mailboxId },
        select: { lastSyncedAt: true },
      }),
    ]);

    return {
      totalEmails,
      unreadEmails: unreadCount,
      sentEmails: sentCount,
      spamEmails: spamCount,
      phishingEmails: phishingCount,
      storageUsed: storageUsed._sum.size ?? 0,
      lastSyncTime: mailbox?.lastSyncedAt ?? null,
    };
  }

  async getActivity(
    userId: number,
    period: 'daily' | 'weekly' | 'monthly',
  ) {
    const now = new Date();
    let startDate: Date;
    let intervalDays: number;

    if (period === 'daily') {
      intervalDays = 30;
      startDate = new Date(now);
      startDate.setDate(startDate.getDate() - intervalDays);
    } else if (period === 'weekly') {
      intervalDays = 12 * 7;
      startDate = new Date(now);
      startDate.setDate(startDate.getDate() - intervalDays);
    } else {
      intervalDays = 12 * 30;
      startDate = new Date(now);
      startDate.setMonth(startDate.getMonth() - 12);
    }

    const emails = await this.prisma.email.findMany({
      where: {
        mailBox: { userId },
        receivedAt: { gte: startDate },
      },
      select: {
        receivedAt: true,
        folderId: true,
        isSpam: true,
        isPhishing: true,
      },
    });

    const sentFolderIds = await this.prisma.folder
      .findMany({
        where: { mailBox: { userId }, type: FolderType.SENT },
        select: { id: true },
      })
      .then((f) => f.map((x) => x.id));

    const bucketKey = (d: Date): string => {
      const copy = new Date(d);
      if (period === 'daily') {
        copy.setHours(0, 0, 0, 0);
        return copy.toISOString().slice(0, 10);
      }
      if (period === 'weekly') {
        const day = copy.getDay();
        const diff = copy.getDate() - day + (day === 0 ? -6 : 1);
        copy.setDate(diff);
        copy.setHours(0, 0, 0, 0);
        return copy.toISOString().slice(0, 10);
      }
      copy.setDate(1);
      copy.setHours(0, 0, 0, 0);
      return copy.toISOString().slice(0, 7);
    };

    const buckets: Record<
      string,
      { received: number; sent: number; spam: number; phishing: number }
    > = {};

    for (const e of emails) {
      const key = bucketKey(e.receivedAt);
      if (!buckets[key]) {
        buckets[key] = { received: 0, sent: 0, spam: 0, phishing: 0 };
      }
      const isSent = sentFolderIds.includes(e.folderId);
      if (isSent) {
        buckets[key].sent++;
      } else {
        buckets[key].received++;
      }
      if (e.isSpam) buckets[key].spam++;
      if (e.isPhishing) buckets[key].phishing++;
    }

    const sorted = Object.entries(buckets)
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([date, counts]) => ({ date, ...counts }));

    return { data: sorted };
  }

  async getFlaggedEmailsReport(userId: number, mailboxId: number) {
    await this.ensureMailboxAccess(userId, mailboxId);

    const emails = await this.prisma.email.findMany({
      where: {
        mailBoxId: mailboxId,
        OR: [{ isSpam: true }, { isPhishing: true }],
      },
      select: {
        id: true,
        subject: true,
        fromAddr: true,
        fromName: true,
        receivedAt: true,
        isSpam: true,
        isPhishing: true,
        spamScore: true,
        phishingScore: true,
        malwareVerdict: true,
        malwareScore: true,
        malwareSeverity: true,
        aiReport: true,
      },
      orderBy: { receivedAt: 'desc' },
    });

    return {
      data: emails.map((e) => ({
        id: e.id,
        subject: e.subject,
        from: e.fromAddr,
        fromName: e.fromName,
        date: e.receivedAt,
        classification: e.isPhishing ? 'phishing' : e.isSpam ? 'spam' : 'unknown',
        classificationReason: e.isPhishing
          ? `Phishing score: ${e.phishingScore}`
          : `Spam score: ${e.spamScore}`,
        classificationScore: e.isPhishing ? e.phishingScore : e.spamScore,
        malwareVerdict: e.malwareVerdict,
        malwareScore: e.malwareScore,
        malwareSeverity: e.malwareSeverity,
        aiReport: e.aiReport,
      })),
    };
  }
}
