import { Injectable } from '@nestjs/common';
import { InjectQueue } from '@nestjs/bullmq';
import { Queue } from 'bullmq';
import { PrismaService } from '../prisma.service';
import { EmailProviders } from 'generated/prisma/enums';
import { FolderType } from 'generated/prisma/enums';

export const EMAIL_SYNC_QUEUE = 'email-sync';

@Injectable()
export class EmailSyncService {
  constructor(
    private prisma: PrismaService,
    @InjectQueue(EMAIL_SYNC_QUEUE) private syncQueue: Queue,
  ) {}

  async scheduleSyncAll() {
    const mailboxes = await this.prisma.mailBox.findMany({
      where: { isActive: true },
      select: { id: true },
    });
    for (const mb of mailboxes) {
      await this.scheduleSync(mb.id);
    }
  }

  async scheduleSync(mailBoxId: number) {
    await this.syncQueue.add('sync-mailbox', { mailBoxId }, { jobId: `sync-${mailBoxId}` });
  }
}
