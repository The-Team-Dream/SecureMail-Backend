import { Module } from '@nestjs/common';
import { PrismaModule } from '../prisma.module';
import { AuthModule } from '../auth/auth.module';
import { SessionsModule } from '../sessions/sessions.module';
import { NotificationsModule } from '../notifications/notifications.module';
import { AdminUsersController } from './controllers/admin-users.controller';
import { AdminStatsController } from './controllers/admin-stats.controller';
import { AdminEmailsController } from './controllers/admin-emails.controller';
import { AdminMailboxesController } from './controllers/admin-mailboxes.controller';
import { AdminNotificationsController } from './controllers/admin-notifications.controller';
import { AdminAuditController } from './controllers/admin-audit.controller';
import { AdminDashboardController } from './controllers/admin-dashboard.controller';
import { AdminUsersService } from './services/admin-users.service';
import { AdminStatsService } from './services/admin-stats.service';
import { AdminEmailsService } from './services/admin-emails.service';
import { AdminMailboxesService } from './services/admin-mailboxes.service';
import { AdminNotificationsService } from './services/admin-notifications.service';
import { AdminAuditService } from './services/admin-audit.service';
import { AdminDashboardService } from './services/admin-dashboard.service';
import { AuditLogService } from './services/audit-log.service';

@Module({
  imports: [PrismaModule, AuthModule, SessionsModule, NotificationsModule],
  controllers: [
    AdminUsersController,
    AdminStatsController,
    AdminEmailsController,
    AdminMailboxesController,
    AdminNotificationsController,
    AdminAuditController,
    AdminDashboardController,
  ],
  providers: [
    AuditLogService,
    AdminUsersService,
    AdminStatsService,
    AdminEmailsService,
    AdminMailboxesService,
    AdminNotificationsService,
    AdminAuditService,
    AdminDashboardService,
  ],
})
export class AdminModule {}
