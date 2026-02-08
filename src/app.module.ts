import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { EmailAccountsModule } from './email-accounts/email-accounts.module';
import { MailModule } from './mail/mail.module';
import { FoldersModule } from './folders/folders.module';
import { NotificationsModule } from './notifications/notifications.module';
import { HealthModule } from './health/health.module';
import { PrismaModule } from './prisma.module';
import { ConfigModule } from '@nestjs/config';

@Module({
  imports: [AuthModule, UsersModule, EmailAccountsModule, MailModule, FoldersModule, NotificationsModule, HealthModule, PrismaModule, ConfigModule.forRoot({
    isGlobal: true,
  }),],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule { }
//test test test
