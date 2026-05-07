import {
  BadRequestException,
  Injectable,
  NotFoundException,
  StreamableFile,
} from '@nestjs/common';
import { PrismaService } from '../../prisma.service';
import { FolderType } from '@prisma/client';
import { ReportType } from './dto/report-email.dto';
import { TargetFolderType } from './dto/reclassify-email.dto';

@Injectable()
export class EmailsService {
  constructor(
    private prisma: PrismaService,
  ) {}

  async ensureMailboxAccess(userId: number, mailboxId: number) {
    const mailbox = await this.prisma.mailBox.findFirst({
      where: { id: mailboxId, userId },
    });
    if (!mailbox) {
      throw new NotFoundException('Mailbox not found');
    }
    return mailbox;
  }

  private async getFolderByType(
    mailboxId: number,
    folderType: FolderType,
  ) {
    const folder = await this.prisma.folder.findFirst({
      where: { mailBoxId: mailboxId, type: folderType },
    });
    if (!folder) {
      throw new NotFoundException(
        `Folder ${folderType.toLowerCase()} not found for this mailbox`,
      );
    }
    return folder;
  }

  async listByFolder(
    userId: number,
    mailboxId: number,
    folderType: FolderType,
    page: number,
    limit: number,
  ) {
    await this.ensureMailboxAccess(userId, mailboxId);
    const folder = await this.getFolderByType(mailboxId, folderType);

    const skip = (page - 1) * limit;
    const [emails, total] = await Promise.all([
      this.prisma.email.findMany({
        where: { mailBoxId: mailboxId, folderId: folder.id },
        orderBy: { receivedAt: 'desc' },
        skip,
        take: limit,
        select: {
          id: true,
          mailBoxId: true,
          subject: true,
          fromAddr: true,
          fromName: true,
          toAddr: true,
          isRead: true,
          isFlagged: true,
          isSpam: true,
          isPhishing: true,
          receivedAt: true,
          spamScore: true,
          phishingScore: true,
          malwareVerdict: true,
          malwareScore: true,
          malwareSeverity: true,
        },
      }),
      this.prisma.email.count({
        where: { mailBoxId: mailboxId, folderId: folder.id },
      }),
    ]);

    return {
      data: emails,
      meta: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  async listStarred(
    userId: number,
    mailboxId: number,
    page: number,
    limit: number,
  ) {
    await this.ensureMailboxAccess(userId, mailboxId);

    const skip = (page - 1) * limit;
    const [emails, total] = await Promise.all([
      this.prisma.email.findMany({
        where: { mailBoxId: mailboxId, isFlagged: true },
        orderBy: { receivedAt: 'desc' },
        skip,
        take: limit,
        select: {
          id: true,
          mailBoxId: true,
          subject: true,
          fromAddr: true,
          fromName: true,
          toAddr: true,
          isRead: true,
          isFlagged: true,
          isSpam: true,
          isPhishing: true,
          receivedAt: true,
          spamScore: true,
          phishingScore: true,
          malwareVerdict: true,
          malwareScore: true,
          malwareSeverity: true,
          folder: { select: { id: true, type: true } },
        },
      }),
      this.prisma.email.count({
        where: { mailBoxId: mailboxId, isFlagged: true },
      }),
    ]);

    return {
      data: emails,
      meta: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  async search(
    userId: number,
    mailboxId: number,
    q: string | undefined,
    page: number,
    limit: number,
  ) {
    await this.ensureMailboxAccess(userId, mailboxId);

    const skip = (page - 1) * limit;
    
    // If no query provided, just return all emails in mailbox
    const whereClause: any = { mailBoxId: mailboxId };
    
    if (q && q.trim().length > 0) {
      const searchStr = q.trim();
      whereClause.OR = [
        { subject: { contains: searchStr, mode: 'insensitive' } },
        { fromAddr: { contains: searchStr, mode: 'insensitive' } },
        { fromName: { contains: searchStr, mode: 'insensitive' } },
      ];
    }

    const [emails, total] = await Promise.all([
      this.prisma.email.findMany({
        where: whereClause,
        orderBy: { receivedAt: 'desc' },
        skip,
        take: limit,
        select: {
          id: true,
          mailBoxId: true,
          subject: true,
          fromAddr: true,
          fromName: true,
          toAddr: true,
          isRead: true,
          isFlagged: true,
          isSpam: true,
          isPhishing: true,
          receivedAt: true,
          spamScore: true,
          phishingScore: true,
          malwareVerdict: true,
          malwareScore: true,
          malwareSeverity: true,
          folder: { select: { id: true, type: true } },
        },
      }),
      this.prisma.email.count({
        where: whereClause,
      }),
    ]);

    return {
      data: emails,
      meta: {
        total,
        page,
        limit,
        totalPages: Math.ceil(total / limit),
      },
    };
  }

  async findOne(userId: number, mailboxId: number, emailId: number) {
    await this.ensureMailboxAccess(userId, mailboxId);
    const email = await this.prisma.email.findFirst({
      where: { id: emailId, mailBoxId: mailboxId },
      include: {
        attachments: true,
        folder: { select: { id: true, name: true, type: true } },
      },
    });
    if (!email) {
      throw new NotFoundException('Email not found');
    }
    return {
      ...email,
      aiReportStatus: email.aiReport ? 'COMPLETED' : 'PENDING',
    };
  }

  async markRead(
    userId: number,
    mailboxId: number,
    emailId: number,
    read: boolean,
  ) {
    await this.ensureMailboxAccess(userId, mailboxId);
    const email = await this.prisma.email.findFirst({
      where: { id: emailId, mailBoxId: mailboxId },
    });
    if (!email) {
      throw new NotFoundException('Email not found');
    }
    await this.prisma.email.update({
      where: { id: emailId },
      data: { isRead: read },
    });
    return this.findOne(userId, mailboxId, emailId);
  }

  async delete(userId: number, mailboxId: number, emailId: number) {
    await this.ensureMailboxAccess(userId, mailboxId);
    const email = await this.prisma.email.findFirst({
      where: { id: emailId, mailBoxId: mailboxId },
      include: { folder: true },
    });
    if (!email) {
      throw new NotFoundException('Email not found');
    }

    const trashFolder = await this.prisma.folder.findFirst({
      where: { mailBoxId: mailboxId, type: FolderType.TRASH },
    });

    if (trashFolder) {
      await this.prisma.email.update({
        where: { id: emailId },
        data: { folderId: trashFolder.id },
      });
      return { message: 'Email moved to trash', action: 'trashed' as const, emailId };
    }

    await this.prisma.email.delete({ where: { id: emailId } });
    return { message: 'Email deleted', action: 'deleted' as const, emailId };
  }

  async report(
    userId: number,
    mailboxId: number,
    emailId: number,
    type: ReportType,
  ) {
    await this.ensureMailboxAccess(userId, mailboxId);
    const email = await this.prisma.email.findFirst({
      where: { id: emailId, mailBoxId: mailboxId },
      include: { folder: true },
    });
    if (!email) {
      throw new NotFoundException('Email not found');
    }

    if (type === ReportType.SPAM) {
      const spamFolder = await this.getOrCreateFolder(mailboxId, FolderType.SPAM);
      await this.prisma.email.update({
        where: { id: emailId },
        data: {
          folderId: spamFolder.id,
          isSpam: true,
          spamScore: 100,
        },
      });
    } else if (type === ReportType.PHISHING) {
      const phishingFolder = await this.getOrCreateFolder(
        mailboxId,
        FolderType.PHISHING,
      );
      await this.prisma.email.update({
        where: { id: emailId },
        data: {
          folderId: phishingFolder.id,
          isPhishing: true,
          phishingScore: 100,
        },
      });
    }

    return this.findOne(userId, mailboxId, emailId);
  }

  async reclassify(
    userId: number,
    mailboxId: number,
    emailId: number,
    targetFolder: TargetFolderType,
  ) {
    await this.ensureMailboxAccess(userId, mailboxId);
    const email = await this.prisma.email.findFirst({
      where: { id: emailId, mailBoxId: mailboxId },
    });
    if (!email) {
      throw new NotFoundException('Email not found');
    }

    const folderTypeMap: Record<TargetFolderType, FolderType> = {
      [TargetFolderType.INBOX]: FolderType.INBOX,
      [TargetFolderType.SENT]: FolderType.SENT,
      [TargetFolderType.SPAM]: FolderType.SPAM,
      [TargetFolderType.PHISHING]: FolderType.PHISHING,
      [TargetFolderType.TRASH]: FolderType.TRASH,
    };

    const folderType = folderTypeMap[targetFolder];
    const folder = await this.getOrCreateFolder(mailboxId, folderType);

    const updateData: { folderId: number; isSpam?: boolean; isPhishing?: boolean } = {
      folderId: folder.id,
    };
    if (folderType === FolderType.SPAM) updateData.isSpam = true;
    else if (folderType === FolderType.PHISHING) updateData.isPhishing = true;
    else {
      updateData.isSpam = false;
      updateData.isPhishing = false;
    }

    await this.prisma.email.update({
      where: { id: emailId },
      data: updateData,
    });

    return this.findOne(userId, mailboxId, emailId);
  }

  private async getOrCreateFolder(
    mailboxId: number,
    type: FolderType,
  ) {
    let folder = await this.prisma.folder.findFirst({
      where: { mailBoxId: mailboxId, type },
    });
    if (!folder) {
      folder = await this.prisma.folder.create({
        data: {
          mailBoxId: mailboxId,
          name: type.toLowerCase(),
          type,
          remoteId: type,
        },
      });
    }
    return folder;
  }

  async downloadAttachment(
    userId: number,
    mailboxId: number,
    emailId: number,
    attachmentId: number,
  ) {
    await this.ensureMailboxAccess(userId, mailboxId);
    
    const attachment = await this.prisma.attachment.findFirst({
      where: { 
        id: attachmentId, 
        emailId: emailId,
        email: { mailBoxId: mailboxId }
      },
    });

    if (!attachment) {
      throw new NotFoundException('Attachment not found');
    }

    // If it's a Cloudinary URL or remote URL, return redirect directive
    if (attachment.storagePath.startsWith('http://') || attachment.storagePath.startsWith('https://')) {
      return { url: attachment.storagePath, type: 'redirect' };
    }

    // Since we've migrated to Cloudinary, local file streaming is deprecated.
    // If we reach here, it means storagePath was not a URL, which shouldn't happen for new records.
    throw new NotFoundException('Attachment source not available (deprecated local storage)');
  }
}
