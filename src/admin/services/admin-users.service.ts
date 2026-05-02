import {
  ConflictException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../../prisma.service';
import { Role } from '@prisma/client';
import { AuditLogService } from './audit-log.service';
import { AuditTargetType } from '@prisma/client';
import { SessionsService } from '../../sessions/sessions.service';

@Injectable()
export class AdminUsersService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly auditLog: AuditLogService,
    private readonly sessionsService: SessionsService,
  ) {}

  async findAll(
    page: number,
    limit: number,
    search?: string,
    active?: boolean,
    banned?: boolean,
  ) {
    const where: {
      deletedAt?: null | { not: null };
      bannedAt?: null | { not: null };
      OR?: Array<{ email?: { contains: string; mode: 'insensitive' }; username?: { contains: string; mode: 'insensitive' } }>;
    } = {};

    if (search?.trim()) {
      const s = search.trim();
      where.OR = [
        { email: { contains: s, mode: 'insensitive' } },
        { username: { contains: s, mode: 'insensitive' } },
      ];
    }
    if (active === true) {
      where.deletedAt = null;
      where.bannedAt = null;
    } else if (banned === true) {
      where.bannedAt = { not: null };
    }

    const skip = (page - 1) * limit;
    
    const [data, total] = await Promise.all([
      this.prisma.user.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
        select: {
          id: true,
          email: true,
          username: true,
          provider: true,
          isVerified: true,
          role: true,
          bannedAt: true,
          deletedAt: true,
          createdAt: true,
          _count: {
            select: { mailBoxes: true, sessions: true },
          },
        },
      }),
      this.prisma.user.count({ where }),
    ]);

    return {
      users: data.map((u) => ({
        ...u,
        mailboxesCount: u._count.mailBoxes,
        sessionsCount: u._count.sessions,
        _count: undefined,
      })),
      meta: { total, page, limit, totalPages: Math.ceil(total / limit) },
    };
  }

  async findOne(id: number) {
    const user = await this.prisma.user.findFirst({
      where: { id },
      select: {
        id: true,
        email: true,
        username: true,
        avatar: true,
        provider: true,
        isVerified: true,
        totpEnabled: true,
        role: true,
        bannedAt: true,
        deletedAt: true,
        createdAt: true,
        sessions: {
          where: { expiresAt: { gt: new Date() } },
          orderBy: { loginAt: 'desc' },
          take: 10,
          select: {
            id: true,
            ipAddress: true,
            deviceOs: true,
            deviceBrowser: true,
            loginAt: true,
            expiresAt: true,
          },
        },
        _count: { select: { mailBoxes: true } },
      },
    });
    if (!user) {
      throw new NotFoundException('User not found');
    }
    const lastLogin = user.sessions[0]?.loginAt ?? null;
    return {
      ...user,
      lastLogin,
      mailboxesCount: user._count.mailBoxes,
    };
  }

  async ban(adminId: number, userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });
    if (!user) throw new NotFoundException('User not found');
    if (user.deletedAt) throw new ConflictException('User is deleted');
    if (user.bannedAt) throw new ConflictException('User already banned');
    if (user.role === Role.ADMIN) throw new ConflictException('Cannot ban admin');

    await this.prisma.user.update({
      where: { id: userId },
      data: { bannedAt: new Date() },
    });

    await this.auditLog.log({
      adminId,
      action: 'USER_BANNED',
      targetType: AuditTargetType.USER,
      targetId: userId,
      details: { email: user.email },
    });

    return { message: 'User banned' };
  }

  async unban(adminId: number, userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });
    if (!user) throw new NotFoundException('User not found');
    if (!user.bannedAt) throw new ConflictException('User is not banned');

    await this.prisma.user.update({
      where: { id: userId },
      data: { bannedAt: null },
    });

    await this.auditLog.log({
      adminId,
      action: 'USER_UNBANNED',
      targetType: AuditTargetType.USER,
      targetId: userId,
      details: { email: user.email },
    });

    return { message: 'User unbanned' };
  }

  async softDelete(adminId: number, userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });
    if (!user) throw new NotFoundException('User not found');
    if (user.deletedAt) throw new ConflictException('User already deleted');
    if (user.role === Role.ADMIN) throw new ConflictException('Cannot delete admin');

    await this.prisma.user.update({
      where: { id: userId },
      data: { deletedAt: new Date(), bannedAt: null },
    });

    // Revoke all active sessions so existing JWTs are immediately invalidated
    await this.sessionsService.revokeAllSessionsForUser(userId);

    await this.auditLog.log({
      adminId,
      action: 'USER_DELETED',
      targetType: AuditTargetType.USER,
      targetId: userId,
      details: { email: user.email },
    });

    return { message: 'User deleted' };
  }

  async getSessions(userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });
    if (!user) throw new NotFoundException('User not found');
    return this.sessionsService.getSessionsForUser(userId);
  }

  async revokeAllSessions(adminId: number, userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });
    if (!user) throw new NotFoundException('User not found');
    const result = await this.sessionsService.revokeAllSessionsForUser(userId);

    await this.auditLog.log({
      adminId,
      action: 'SESSIONS_REVOKED',
      targetType: AuditTargetType.USER,
      targetId: userId,
      details: { revokedCount: result.revokedCount, email: user.email },
    });

    return result;
  }

  async getMailboxes(userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });
    if (!user) throw new NotFoundException('User not found');
    return this.prisma.mailBox.findMany({
      where: { userId },
      include: {
        _count: { select: { emails: true } },
      },
    });
  }

  async getNotifications(userId: number, page: number, limit: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
    });
    if (!user) throw new NotFoundException('User not found');
    const skip = (page - 1) * limit;
    const [data, total] = await Promise.all([
      this.prisma.notification.findMany({
        where: { userId },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      this.prisma.notification.count({ where: { userId } }),
    ]);
    return {
      data,
      meta: { total, page, limit, totalPages: Math.ceil(total / limit) },
    };
  }
}
