import { Injectable } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { EmailSyncService } from './email-sync.service';

@Injectable()
export class EmailSyncScheduler {
  constructor(private emailSyncService: EmailSyncService) {}

  @Cron('*/15 * * * *') // Every 15 minutes
  async handleScheduledSync() {
    await this.emailSyncService.scheduleSyncAll();
  }
}
