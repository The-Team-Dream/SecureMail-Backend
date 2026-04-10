import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../../prisma.service';
import { FolderType } from 'generated/prisma/enums';
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
    return email;
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
    return this.prisma.email.update({
      where: { id: emailId },
      data: { isRead: read },
    });
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
      return { message: 'Email moved to trash' };
    }

    await this.prisma.email.delete({ where: { id: emailId } });
    return { message: 'Email deleted' };
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

    return { message: `Email reported as ${type}` };
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

    return { message: `Email moved to ${targetFolder}` };
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
}
