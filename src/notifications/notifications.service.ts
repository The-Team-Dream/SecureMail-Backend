import {
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { NotificationType } from 'generated/prisma/enums';
import { NotificationsGateway } from './notifications.gateway';

export interface CreateNotificationInput {
  userId: number;
  type: NotificationType;
  title: string;
  message: string;
  metadata?: Record<string, unknown>;
  mailBoxId?: number;
  emailId?: number;
}

@Injectable()
export class NotificationsService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly gateway: NotificationsGateway,
  ) {}

  async create(input: CreateNotificationInput) {
    const notification = await this.prisma.notification.create({
      data: {
        userId: input.userId,
        type: input.type,
        title: input.title,
        message: input.message,
        metadata: input.metadata ? JSON.parse(JSON.stringify(input.metadata)) : undefined,
        mailBoxId: input.mailBoxId,
        emailId: input.emailId,
      },
    });

    try {
      this.gateway.emitToUser(input.userId, notification);
    } catch {
      // Emit failure is non-fatal
    }
    return notification;
  }

  async findAll(
    userId: number,
    page: number,
    limit: number,
  ) {
    const skip = (page - 1) * limit;
    const [data, total] = await Promise.all([
      this.prisma.notification.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
        select: {
          id: true,
          type: true,
          title: true,
          message: true,
          isRead: true,
          metadata: true,
          mailBoxId: true,
          emailId: true,
          createdAt: true,
        },
      }),
      this.prisma.notification.count({ where: { userId } }),
    ]);

    return {
      data,
      meta: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  async getUnreadCount(userId: number): Promise<number> {
    return this.prisma.notification.count({
      where: { userId, isRead: false },
    });
  }

  async markAsRead(userId: number, id: number) {
    const notification = await this.prisma.notification.findUnique({
      where: { id },
    });
    if (!notification) {
      throw new NotFoundException('Notification not found');
    }
    if (notification.userId !== userId) {
      throw new ForbiddenException('Access denied');
    }
    return this.prisma.notification.update({
      where: { id },
      data: { isRead: true },
    });
  }

  async markAllAsRead(userId: number) {
    const result = await this.prisma.notification.updateMany({
      where: { userId, isRead: false },
      data: { isRead: true },
    });
    return { updatedCount: result.count };
  }

  async delete(userId: number, id: number) {
    const notification = await this.prisma.notification.findUnique({
      where: { id },
    });
    if (!notification) {
      throw new NotFoundException('Notification not found');
    }
    if (notification.userId !== userId) {
      throw new ForbiddenException('Access denied');
    }
    await this.prisma.notification.delete({ where: { id } });
    return { message: 'Notification deleted' };
  }
}
