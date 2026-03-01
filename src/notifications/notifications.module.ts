import { forwardRef, Module } from '@nestjs/common';
import { NotificationsGateway } from './notifications.gateway';
import { NotificationsService } from './notifications.service';
import { NotificationsController } from './notifications.controller';
import { NotificationTriggersService } from './notification-triggers.service';
import { PrismaModule } from '../prisma.module';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [forwardRef(() => AuthModule), PrismaModule],
  controllers: [NotificationsController],
  providers: [
    NotificationsGateway,
    NotificationsService,
    NotificationTriggersService,
  ],
  exports: [NotificationsService],
})
export class NotificationsModule {}
