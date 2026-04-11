import { Injectable } from '@nestjs/common';
import { Cron } from '@nestjs/schedule';
import { EmailSyncService } from './email-sync.service';

@Injectable()
export class EmailSyncScheduler {
  constructor(private emailSyncService: EmailSyncService) {}

  @Cron('*/5 * * * *') // Every 5 minutes
  async handleScheduledSync() {
    await this.emailSyncService.scheduleSyncAll();
  }
}
