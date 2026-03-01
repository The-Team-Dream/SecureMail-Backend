import { Injectable, NotFoundException } from '@nestjs/common';
import { PrismaService } from '../../prisma.service';
import { AdminEmailClassification } from '../dto/emails-query.dto';

@Injectable()
export class AdminEmailsService {
  constructor(private readonly prisma: PrismaService) {}

  private buildWhere(query: {
    classification?: AdminEmailClassification;
    fromDate?: string;
    toDate?: string;
    mailboxId?: number;
    search?: string;
  }) {
    const where: {
      isSpam?: boolean;
      isPhishing?: boolean;
      receivedAt?: { gte?: Date; lte?: Date };
      mailBoxId?: number;
      OR?: Array<{ subject?: { contains: string; mode: 'insensitive' }; fromAddr?: { contains: string; mode: 'insensitive' } }>;
    } = {};

    if (query.classification === AdminEmailClassification.PHISHING) {
      where.isPhishing = true;
    } else if (query.classification === AdminEmailClassification.SPAM) {
      where.isSpam = true;
    } else if (query.classification === AdminEmailClassification.INBOX) {
      where.isSpam = false;
      where.isPhishing = false;
    }

    if (query.fromDate) {
      const d = new Date(query.fromDate);
      where.receivedAt = { ...where.receivedAt, gte: d };
    }
    if (query.toDate) {
      const d = new Date(query.toDate);
      d.setHours(23, 59, 59, 999);
      where.receivedAt = { ...where.receivedAt, lte: d };
    }
    if (query.mailboxId) {
      where.mailBoxId = query.mailboxId;
    }
    if (query.search?.trim()) {
      const s = query.search.trim();
      where.OR = [
        { subject: { contains: s, mode: 'insensitive' } },
        { fromAddr: { contains: s, mode: 'insensitive' } },
      ];
    }
    return where;
  }

  async findAll(
    page: number,
    limit: number,
    query: Parameters<AdminEmailsService['buildWhere']>[0],
  ) {
    const where = this.buildWhere(query);
    const skip = (page - 1) * limit;
    const [data, total] = await Promise.all([
      this.prisma.email.findMany({
        where,
        orderBy: { receivedAt: 'desc' },
        skip,
        take: limit,
        select: {
          id: true,
          subject: true,
          fromAddr: true,
          fromName: true,
          isSpam: true,
          isPhishing: true,
          receivedAt: true,
          mailBoxId: true,
          mailBox: { select: { displayName: true, emailAddress: true } },
        },
      }),
      this.prisma.email.count({ where }),
    ]);
    return {
      data,
      meta: { total, page, limit, totalPages: Math.ceil(total / limit) },
    };
  }

  async findOne(id: number) {
    const email = await this.prisma.email.findUnique({
      where: { id },
      include: {
        mailBox: { select: { id: true, displayName: true, emailAddress: true } },
        folder: { select: { id: true, name: true, type: true } },
        attachments: { select: { id: true, filename: true, mimeType: true, size: true } },
      },
    });
    if (!email) throw new NotFoundException('Email not found');
    return email;
  }

  async getPhishing(page: number, limit: number) {
    return this.findAll(page, limit, {
      classification: AdminEmailClassification.PHISHING,
    });
  }

  async getSpam(page: number, limit: number) {
    return this.findAll(page, limit, {
      classification: AdminEmailClassification.SPAM,
    });
  }
}
