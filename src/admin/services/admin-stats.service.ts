import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma.service';

@Injectable()
export class AdminStatsService {
  constructor(private readonly prisma: PrismaService) {}

  async getOverview() {
    const now = new Date();
    const todayStart = new Date(now);
    todayStart.setHours(0, 0, 0, 0);
    const weekStart = new Date(now);
    weekStart.setDate(weekStart.getDate() - 7);
    weekStart.setHours(0, 0, 0, 0);
    const monthStart = new Date(now);
    monthStart.setMonth(monthStart.getMonth() - 1);
    monthStart.setHours(0, 0, 0, 0);

    const [
      totalUsers,
      activeUsers,
      bannedUsers,
      totalMailboxes,
      totalEmails,
      phishingToday,
      spamToday,
      newUsersToday,
      newUsersWeek,
      newUsersMonth,
    ] = await Promise.all([
      this.prisma.user.count({ where: { deletedAt: null } }),
      this.prisma.user.count({
        where: {
          deletedAt: null,
          bannedAt: null,
          sessions: {
            some: { loginAt: { gte: weekStart } },
          },
        },
      }),
      this.prisma.user.count({ where: { bannedAt: { not: null } } }),
      this.prisma.mailBox.count({ where: { isActive: true } }),
      this.prisma.email.count(),
      this.prisma.email.count({
        where: {
          isPhishing: true,
          receivedAt: { gte: todayStart },
        },
      }),
      this.prisma.email.count({
        where: {
          isSpam: true,
          receivedAt: { gte: todayStart },
        },
      }),
      this.prisma.user.count({
        where: { createdAt: { gte: todayStart }, deletedAt: null },
      }),
      this.prisma.user.count({
        where: { createdAt: { gte: weekStart }, deletedAt: null },
      }),
      this.prisma.user.count({
        where: { createdAt: { gte: monthStart }, deletedAt: null },
      }),
    ]);

    return {
      totalUsers,
      activeUsers,
      bannedUsers,
      totalMailboxesConnected: totalMailboxes,
      totalEmailsInSystem: totalEmails,
      totalPhishingDetectedToday: phishingToday,
      totalSpamDetectedToday: spamToday,
      newUsersRegisteredToday: newUsersToday,
      newUsersRegisteredThisWeek: newUsersWeek,
      newUsersRegisteredThisMonth: newUsersMonth,
    };
  }

  async getActivity() {
    const now = new Date();
    const startDate = new Date(now);
    startDate.setDate(startDate.getDate() - 30);
    startDate.setHours(0, 0, 0, 0);

    const users = await this.prisma.user.findMany({
      where: { createdAt: { gte: startDate }, deletedAt: null },
      select: { createdAt: true },
    });
    const emails = await this.prisma.email.findMany({
      where: { receivedAt: { gte: startDate } },
      select: {
        receivedAt: true,
        isPhishing: true,
      },
    });
    const sessions = await this.prisma.userSession.findMany({
      where: { loginAt: { gte: startDate } },
      select: { loginAt: true, userId: true },
    });

    const bucketKey = (d: Date) => {
      const c = new Date(d);
      c.setHours(0, 0, 0, 0);
      return c.toISOString().slice(0, 10);
    };

    const activeByDay = new Map<string, Set<number>>();
    for (const s of sessions) {
      const key = bucketKey(s.loginAt);
      if (!activeByDay.has(key)) activeByDay.set(key, new Set());
      activeByDay.get(key)!.add(s.userId);
    }

    const buckets = new Map<
      string,
      { registrations: number; activeUsers: number; emailsProcessed: number; phishingDetected: number }
    >();

    for (let i = 0; i < 30; i++) {
      const d = new Date(startDate);
      d.setDate(d.getDate() + i);
      const key = bucketKey(d);
      buckets.set(key, {
        registrations: 0,
        activeUsers: 0,
        emailsProcessed: 0,
        phishingDetected: 0,
      });
    }

    for (const u of users) {
      const key = bucketKey(u.createdAt);
      const b = buckets.get(key);
      if (b) b.registrations++;
    }

    for (const [key, userIds] of activeByDay) {
      const b = buckets.get(key);
      if (b) b.activeUsers = userIds.size;
    }

    for (const e of emails) {
      const key = bucketKey(e.receivedAt);
      const b = buckets.get(key);
      if (b) {
        b.emailsProcessed++;
        if (e.isPhishing) b.phishingDetected++;
      }
    }

    const data = Array.from(buckets.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([date, v]) => ({ date, ...v }));

    return { data };
  }
}
