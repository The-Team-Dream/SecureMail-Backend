import { Injectable } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { PrismaService } from '../prisma.service';
import { NotificationsService } from './notifications.service';
import { NotificationType } from 'generated/prisma/enums';

@Injectable()
export class NotificationTriggersService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly notificationsService: NotificationsService,
  ) {}

  /**
   * Weekly security report - runs every Sunday at 9:00 AM
   */
  @Cron('0 9 * * 0', { timeZone: 'UTC' })
  async runWeeklySecurityReport() {
    const weekStart = new Date();
    weekStart.setDate(weekStart.getDate() - 7);
    weekStart.setHours(0, 0, 0, 0);

    const users = await this.prisma.user.findMany({
      select: { id: true },
      where: {
        sessions: {
          some: {
            loginAt: { gte: weekStart },
          },
        },
      },
    });

    for (const user of users) {
      const [
        totalLogins,
        sessionsWithDevice,
        phishingCount,
        spamCount,
        passwordChanges,
      ] = await Promise.all([
        this.prisma.userSession.count({
          where: { userId: user.id, loginAt: { gte: weekStart } },
        }),
        this.prisma.userSession.findMany({
          where: { userId: user.id, loginAt: { gte: weekStart } },
          select: { deviceOs: true, deviceBrowser: true, ipAddress: true },
          distinct: ['deviceOs', 'deviceBrowser', 'ipAddress'],
        }),
        this.prisma.email.count({
          where: {
            mailBox: { userId: user.id },
            isPhishing: true,
            receivedAt: { gte: weekStart },
          },
        }),
        this.prisma.email.count({
          where: {
            mailBox: { userId: user.id },
            isSpam: true,
            receivedAt: { gte: weekStart },
          },
        }),
        this.prisma.notification.count({
          where: {
            userId: user.id,
            type: NotificationType.PASSWORD_CHANGED,
            createdAt: { gte: weekStart },
          },
        }),
      ]);

      const newDevices = sessionsWithDevice.length;

      const metadata = {
        totalLogins,
        newDevices,
        phishingDetected: phishingCount,
        spamDetected: spamCount,
        passwordChanges,
        periodStart: weekStart.toISOString(),
        periodEnd: new Date().toISOString(),
      };

      await this.notificationsService.create({
        userId: user.id,
        type: NotificationType.WEEKLY_SECURITY_REPORT,
        title: 'Weekly Security Report',
        message: `This week: ${totalLogins} logins, ${newDevices} device(s), ${phishingCount} phishing, ${spamCount} spam.`,
        metadata,
      });
    }
  }
}
