import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../prisma.service';
import { NotificationsService } from '../../notifications/notifications.service';
import { NotificationType } from 'generated/prisma/enums';
import { AuditLogService } from './audit-log.service';
import { AuditTargetType } from 'generated/prisma/enums';

@Injectable()
export class AdminNotificationsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly notificationsService: NotificationsService,
    private readonly auditLog: AuditLogService,
  ) {}

  async findAll(page: number, limit: number) {
    const skip = (page - 1) * limit;
    const [data, total] = await Promise.all([
      this.prisma.notification.findMany({
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
        include: {
          user: { select: { id: true, email: true } },
        },
      }),
      this.prisma.notification.count(),
    ]);
    return {
      data,
      meta: { total, page, limit, totalPages: Math.ceil(total / limit) },
    };
  }

  async broadcast(
    adminId: number,
    title: string,
    message: string,
    type: NotificationType,
    userIds?: number[],
  ) {
    let targetUsers: { id: number }[];
    if (userIds?.length) {
      targetUsers = await this.prisma.user.findMany({
        where: { id: { in: userIds }, deletedAt: null },
        select: { id: true },
      });
    } else {
      targetUsers = await this.prisma.user.findMany({
        where: { deletedAt: null },
        select: { id: true },
      });
    }

    for (const u of targetUsers) {
      await this.notificationsService.create({
        userId: u.id,
        type,
        title,
        message,
      });
    }

    await this.auditLog.log({
      adminId,
      action: 'NOTIFICATION_BROADCAST',
      targetType: AuditTargetType.NOTIFICATION,
      details: {
        title,
        message,
        type,
        userCount: targetUsers.length,
        userIds: userIds ?? 'all',
      },
    });

    return { message: `Notification sent to ${targetUsers.length} users` };
  }

  async delete(adminId: number, id: number) {
    const notification = await this.prisma.notification.findUnique({
      where: { id },
    });
    if (!notification) throw new NotFoundException('Notification not found');

    await this.prisma.notification.delete({ where: { id } });

    await this.auditLog.log({
      adminId,
      action: 'NOTIFICATION_DELETED',
      targetType: AuditTargetType.NOTIFICATION,
      targetId: id,
      details: { userId: notification.userId },
    });

    return { message: 'Notification deleted' };
  }
}
