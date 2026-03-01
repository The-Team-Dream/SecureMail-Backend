import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../prisma.service';
import { AuditLogService } from './audit-log.service';
import { AuditTargetType } from 'generated/prisma/enums';

@Injectable()
export class AdminMailboxesService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly auditLog: AuditLogService,
  ) {}

  async findAll(page: number, limit: number) {
    const skip = (page - 1) * limit;
    const [data, total] = await Promise.all([
      this.prisma.mailBox.findMany({
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
        include: {
          user: {
            select: { id: true, email: true, username: true },
          },
          _count: { select: { emails: true } },
        },
      }),
      this.prisma.mailBox.count(),
    ]);
    return {
      data,
      meta: { total, page, limit, totalPages: Math.ceil(total / limit) },
    };
  }

  async findOne(id: number) {
    const mailbox = await this.prisma.mailBox.findUnique({
      where: { id },
      include: {
        user: { select: { id: true, email: true, username: true } },
        _count: { select: { emails: true, folders: true } },
      },
    });
    if (!mailbox) throw new NotFoundException('Mailbox not found');

    const storageResult = await this.prisma.attachment.aggregate({
      where: { email: { mailBoxId: id } },
      _sum: { size: true },
    });

    return {
      ...mailbox,
      storageUsed: storageResult._sum.size ?? 0,
    };
  }

  async forceDisconnect(adminId: number, id: number) {
    const mailbox = await this.prisma.mailBox.findUnique({
      where: { id },
    });
    if (!mailbox) throw new NotFoundException('Mailbox not found');

    await this.prisma.mailBox.update({
      where: { id },
      data: { isActive: false },
    });

    await this.auditLog.log({
      adminId,
      action: 'MAILBOX_DISCONNECTED',
      targetType: AuditTargetType.MAILBOX,
      targetId: id,
      details: { userId: mailbox.userId, emailAddress: mailbox.emailAddress },
    });

    return { message: 'Mailbox disconnected' };
  }
}
