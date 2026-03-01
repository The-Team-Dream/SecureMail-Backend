import {
  ForbiddenException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma.service';
import { InjectRedis } from '@nestjs-modules/ioredis';
import Redis from 'ioredis';
import { NotificationsService } from '../notifications/notifications.service';
import { NotificationType } from 'generated/prisma/enums';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const UAParser = require('ua-parser-js') as new (ua?: string) => { getResult: () => { os?: { name?: string }; browser?: { name?: string } } };

export interface CreateSessionInput {
  userId: number;
  ipAddress: string;
  userAgent: string;
  expiresAt: Date;
}

export interface ParsedDeviceInfo {
  os: string | null;
  browser: string | null;
}

@Injectable()
export class SessionsService {
  constructor(
    private readonly prisma: PrismaService,
    @InjectRedis() private readonly redis: Redis,
    private readonly notificationsService: NotificationsService,
  ) {}

  parseDeviceInfo(userAgent: string): ParsedDeviceInfo {
    const parser = new UAParser(userAgent);
    const result = parser.getResult();
    const os = result.os?.name ?? null;
    const browser = result.browser?.name ?? null;
    return { os, browser };
  }

  async createSession(input: CreateSessionInput): Promise<number> {
    const { os, browser } = this.parseDeviceInfo(input.userAgent);
    const session = await this.prisma.userSession.create({
      data: {
        userId: input.userId,
        ipAddress: input.ipAddress,
        userAgent: input.userAgent,
        deviceOs: os,
        deviceBrowser: browser,
        expiresAt: input.expiresAt,
      },
    });

    try {
      await this.notificationsService.create({
        userId: input.userId,
        type: NotificationType.NEW_LOGIN_DETECTED,
        title: 'New Login Detected',
        message: `New login from ${os ?? 'Unknown'} / ${browser ?? 'Unknown'} at ${input.ipAddress}`,
        metadata: {
          sessionId: session.id,
          ipAddress: input.ipAddress,
          deviceOs: os,
          deviceBrowser: browser,
          loginAt: session.loginAt,
        },
      });
    } catch {
      // Notification failure is non-fatal
    }

    return session.id;
  }

  async getSessionsForUser(
    userId: number,
    currentSessionId?: number,
  ): Promise<
    Array<{
      id: number;
      ipAddress: string;
      deviceOs: string | null;
      deviceBrowser: string | null;
      userAgent: string;
      loginAt: Date;
      expiresAt: Date;
      isCurrent: boolean;
    }>
  > {
    const sessions = await this.prisma.userSession.findMany({
      where: {
        userId,
        expiresAt: { gt: new Date() },
      },
      orderBy: { loginAt: 'desc' },
      select: {
        id: true,
        ipAddress: true,
        deviceOs: true,
        deviceBrowser: true,
        userAgent: true,
        loginAt: true,
        expiresAt: true,
      },
    });

    return sessions.map((s) => ({
      ...s,
      isCurrent: s.id === currentSessionId,
    }));
  }

  async revokeSession(sessionId: number, userId: number): Promise<void> {
    const session = await this.prisma.userSession.findUnique({
      where: { id: sessionId },
    });

    if (!session) {
      throw new NotFoundException('Session not found');
    }

    if (session.userId !== userId) {
      throw new ForbiddenException('You can only revoke your own sessions');
    }

    await this.blacklistSession(sessionId, session.expiresAt);
    await this.prisma.userSession.delete({
      where: { id: sessionId },
    });
  }

  async revokeAllSessionsForUser(userId: number): Promise<{ revokedCount: number }> {
    const sessions = await this.prisma.userSession.findMany({
      where: { userId, expiresAt: { gt: new Date() } },
    });
    for (const session of sessions) {
      await this.blacklistSession(session.id, session.expiresAt);
    }
    const result = await this.prisma.userSession.deleteMany({
      where: { userId },
    });
    return { revokedCount: result.count };
  }

  async revokeAllSessionsExcept(
    userId: number,
    currentSessionId: number,
  ): Promise<{ revokedCount: number }> {
    const sessions = await this.prisma.userSession.findMany({
      where: {
        userId,
        id: { not: currentSessionId },
        expiresAt: { gt: new Date() },
      },
    });

    for (const session of sessions) {
      await this.blacklistSession(session.id, session.expiresAt);
    }

    const result = await this.prisma.userSession.deleteMany({
      where: {
        userId,
        id: { not: currentSessionId },
      },
    });

    return { revokedCount: result.count };
  }

  async blacklistSession(sessionId: number, expiresAt: Date): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    const exp = Math.floor(expiresAt.getTime() / 1000);
    const ttl = Math.max(0, exp - now);
    await this.redis.set(`bl:session:${sessionId}`, 'blacklisted', 'EX', ttl);
  }

  async isSessionBlacklisted(sessionId: number): Promise<boolean> {
    const result = await this.redis.get(`bl:session:${sessionId}`);
    return !!result;
  }
}
