import { Injectable, Logger } from '@nestjs/common';
import { Cron, CronExpression } from '@nestjs/schedule';
import { PrismaService } from '../prisma.service';
import { AttachmentStorageService } from '../mailboxes/emails/attachment-storage.service';

@Injectable()
export class RetentionService {
  private readonly logger = new Logger(RetentionService.name);

  constructor(
    private readonly prisma: PrismaService,
    private readonly storage: AttachmentStorageService,
  ) {}

  @Cron(CronExpression.EVERY_DAY_AT_MIDNIGHT)
  async handleRetentionCleanup() {
    this.logger.log('Starting daily attachment retention cleanup...');
    
    // Define the threshold: attachments older than 30 days
    const thresholdDate = new Date();
    thresholdDate.setDate(thresholdDate.getDate() - 30);

    // Find attachments to delete
    const oldAttachments = await this.prisma.attachment.findMany({
      where: {
        createdAt: { lt: thresholdDate },
      },
      select: {
        id: true,
        storagePath: true, // This is the publicId
      },
    });

    if (oldAttachments.length === 0) {
      this.logger.log('No old attachments found for cleanup.');
      return;
    }

    this.logger.log(`Found ${oldAttachments.length} attachments older than 30 days. Cleaning up...`);

    for (const attachment of oldAttachments) {
      try {
        // storagePath stores publicId for Cloudinary
        await this.storage.deleteAttachment(attachment.storagePath);
        
        // Remove from DB
        await this.prisma.attachment.delete({
          where: { id: attachment.id },
        });
      } catch (err) {
        this.logger.error(`Failed to cleanup attachment ${attachment.id}`, err);
      }
    }

    this.logger.log('Daily attachment retention cleanup completed.');
  }
}
