import { Injectable } from '@nestjs/common';
import { PrismaService } from '../../prisma.service';
import { AuditTargetType } from '@prisma/client';

export interface CreateAuditLogInput {
  adminId: number;
  action: string;
  targetType: AuditTargetType;
  targetId?: number;
  details?: Record<string, unknown>;
}

@Injectable()
export class AuditLogService {
  constructor(private readonly prisma: PrismaService) {}

  async log(input: CreateAuditLogInput) {
    return this.prisma.auditLog.create({
      data: {
        adminId: input.adminId,
        action: input.action,
        targetType: input.targetType,
        targetId: input.targetId,
        details: input.details ? JSON.parse(JSON.stringify(input.details)) : undefined,
      },
    });
  }
}
