import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { EmailAccountsModule } from './email-accounts/email-accounts.module';
import { MailModule } from './mail/mail.module';
import { FoldersModule } from './folders/folders.module';
import { NotificationsModule } from './notifications/notifications.module';
import { HealthModule } from './health/health.module';
import { PrismaModule } from './prisma.module';
import { ConfigModule } from '@nestjs/config';
import { MailerModule } from '@nestjs-modules/mailer';
import { NodeMailerModule } from './node-mailer/node-mailer.module';

@Module({
  imports: [AuthModule, UserModule, EmailAccountsModule, MailModule, FoldersModule, NotificationsModule, HealthModule, PrismaModule, ConfigModule.forRoot({
    isGlobal: true,
  }), MailerModule, NodeMailerModule,],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule { }
