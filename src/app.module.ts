import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UserModule } from './user/user.module';
import { FoldersModule } from './folders/folders.module';
import { NotificationsModule } from './notifications/notifications.module';
import { HealthModule } from './health/health.module';
import { PrismaModule } from './prisma.module';
import { ConfigModule } from '@nestjs/config';
import { MailerModule } from '@nestjs-modules/mailer';
import { NodeMailerModule } from './node-mailer/node-mailer.module';
import { ThrottlerGuard, ThrottlerModule } from '@nestjs/throttler';
import { APP_GUARD } from '@nestjs/core';
import { MailboxesModule } from './mailboxes/mailboxes.module';
import { EmailsModule } from './mailboxes/emails/emails.module';
import { UserSettingsModule } from './user-settings/user-settings.module';
import { SessionsModule } from './sessions/sessions.module';
import { AnalyticsModule } from './analytics/analytics.module';
import { AdminModule } from './admin/admin.module';
import { ServeStaticModule } from '@nestjs/serve-static';
import { BullModule } from '@nestjs/bullmq';
import { ScheduleModule } from '@nestjs/schedule';
import { EncryptionModule } from './common/encryption/encryption.module';
import { join } from 'path';
import { AiAgentModule } from './ai-agent/ai-agent.module';
import { MalwareModule } from './malware/malware.module';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
    }),
    ThrottlerModule.forRoot({
      throttlers: [
        {
          limit: 20,
          ttl: 60000,
        },
      ],
    }),
    BullModule.forRoot({
      connection: {
        host: process.env.REDIS_HOST ?? 'localhost',
        port: parseInt(process.env.REDIS_PORT ?? '6379', 10),
      },
    }),
    ScheduleModule.forRoot(),
    EncryptionModule,
    AuthModule,
    UserModule,
    FoldersModule,
    NotificationsModule,
    HealthModule,
    PrismaModule,
    MailerModule,
    NodeMailerModule,
    MailboxesModule,
    EmailsModule,
    UserSettingsModule,
    SessionsModule,
    AnalyticsModule,
    AdminModule,
    ServeStaticModule.forRoot({
      rootPath: join(process.cwd(), 'uploads'),
      serveRoot: '/uploads',
    }),
    AiAgentModule,
    MalwareModule,
  ],
  controllers: [AppController],
  providers: [
    AppService,
    {
      provide: APP_GUARD,
      useClass: ThrottlerGuard
    }

  ],
})
export class AppModule { }
