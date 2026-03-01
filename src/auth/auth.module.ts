import { Module, forwardRef } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PrismaModule } from 'src/prisma.module';
import { JwtModule } from '@nestjs/jwt';
import { NodeMailerModule } from 'src/node-mailer/node-mailer.module';
import { PassportModule } from '@nestjs/passport';
import { GoogleStrategy } from './strategies/google-strategy';
import { RedisModule } from '@nestjs-modules/ioredis';
import { SessionsModule } from 'src/sessions/sessions.module';

@Module({
  imports: [
    JwtModule.register({
      global: true,
      secret: "secret",
      signOptions: { expiresIn: '60s' },
    }),
    RedisModule.forRoot({
      type: 'single',
      url: 'redis://localhost:6379',
    }),
    PassportModule,
    PrismaModule,
    NodeMailerModule,
    forwardRef(() => SessionsModule),
  ],
  controllers: [AuthController],
  providers: [AuthService, GoogleStrategy],
  exports: [AuthService,],
})
export class AuthModule {}
