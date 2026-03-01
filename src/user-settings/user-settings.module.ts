import { Module } from '@nestjs/common';
import { UserSettingsController } from './user-settings.controller';
import { UserSettingsService } from './user-settings.service';
import { StorageService } from './storage.service';
import { PrismaModule } from 'src/prisma.module';
import { AuthModule } from 'src/auth/auth.module';
import { NotificationsModule } from '../notifications/notifications.module';

@Module({
  imports: [PrismaModule, AuthModule, NotificationsModule],
  controllers: [UserSettingsController],
  providers: [UserSettingsService, StorageService],
  exports: [UserSettingsService],
})
export class UserSettingsModule {}
