import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma.service';
import { AdminStatsService } from './admin-stats.service';

@Injectable()
export class AdminDashboardService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly statsService: AdminStatsService,
  ) {}

  async getDashboard() {
    const [overview, lastUsers, lastPhishing, lastAuditLogs, storageResult, avgEmails] =
      await Promise.all([
        this.statsService.getOverview(),
        this.prisma.user.findMany({
          where: { deletedAt: null },
          orderBy: { createdAt: 'desc' },
          take: 5,
          select: {
            id: true,
            email: true,
            username: true,
            createdAt: true,
          },
        }),
        this.prisma.email.findMany({
          where: { isPhishing: true },
          orderBy: { receivedAt: 'desc' },
          take: 5,
          select: {
            id: true,
            subject: true,
            fromAddr: true,
            receivedAt: true,
            phishingScore: true,
          },
        }),
        this.prisma.auditLog.findMany({
          orderBy: { createdAt: 'desc' },
          take: 5,
          include: {
            admin: { select: { email: true } },
          },
        }),
        this.prisma.attachment.aggregate({
          _sum: { size: true },
        }),
        (async () => {
          const userCount = await this.prisma.user.count({
            where: { deletedAt: null },
          });
          if (userCount === 0) return 0;
          const emailCount = await this.prisma.email.count();
          return Math.round((emailCount / userCount) * 10) / 10;
        })(),
      ]);

    return {
      overview,
      lastRegisteredUsers: lastUsers,
      lastPhishingEmails: lastPhishing,
      lastAuditLogs: lastAuditLogs.map((l) => ({
        ...l,
        adminEmail: l.admin.email,
      })),
      systemHealth: {
        totalStorageUsed: storageResult._sum.size ?? 0,
        averageEmailsPerUser: avgEmails,
      },
    };
  }
}
