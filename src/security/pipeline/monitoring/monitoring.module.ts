import { Module }             from '@nestjs/common';
import { PostDeliveryService } from './post-delivery.service';
import { PrismaModule }        from '../../../prisma.module';
import { NotificationsModule } from '../../../notifications/notifications.module';

@Module({
  imports:   [PrismaModule, NotificationsModule],
  providers: [PostDeliveryService],
  exports:   [PostDeliveryService],
})
export class MonitoringModule {}
