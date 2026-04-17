import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma.service';
import { AuditTargetType } from '@prisma/client';

@Injectable()
export class AdminAuditService {
  constructor(private readonly prisma: PrismaService) {}

  async findAll(
    page: number,
    limit: number,
    action?: string,
    targetType?: AuditTargetType,
    fromDate?: string,
    toDate?: string,
  ) {
    const where: {
      action?: string;
      targetType?: AuditTargetType;
      createdAt?: { gte?: Date; lte?: Date };
    } = {};
    if (action) where.action = action;
    if (targetType) where.targetType = targetType;
    if (fromDate) {
      where.createdAt = { ...where.createdAt, gte: new Date(fromDate) };
    }
    if (toDate) {
      const d = new Date(toDate);
      d.setHours(23, 59, 59, 999);
      where.createdAt = { ...where.createdAt, lte: d };
    }

    const skip = (page - 1) * limit;
    const [data, total] = await Promise.all([
      this.prisma.auditLog.findMany({
        where,
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
        include: {
          admin: { select: { id: true, email: true } },
        },
      }),
      this.prisma.auditLog.count({ where }),
    ]);
    return {
      data,
      meta: { total, page, limit, totalPages: Math.ceil(total / limit) },
    };
  }

  async findByAdmin(adminId: number, page: number, limit: number) {
    const skip = (page - 1) * limit;
    const [data, total] = await Promise.all([
      this.prisma.auditLog.findMany({
        where: { adminId },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      this.prisma.auditLog.count({ where: { adminId } }),
    ]);
    return {
      data,
      meta: { total, page, limit, totalPages: Math.ceil(total / limit) },
    };
  }
}
