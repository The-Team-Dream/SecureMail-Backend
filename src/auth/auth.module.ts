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
import { ConfigService } from '@nestjs/config';
import { EncryptionModule } from 'src/common/encryption/encryption.module';

@Module({
  imports: [
    JwtModule.registerAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        secret: config.getOrThrow('JWT_SECRET'),
        signOptions: { expiresIn: config.get('JWT_EXPIRES_IN', '7d') },
      }),
    }),
    RedisModule.forRootAsync({
      inject: [ConfigService],
      useFactory: (config: ConfigService) => ({
        type: 'single',
        url: `redis://${config.get('REDIS_HOST', 'localhost')}:${config.get('REDIS_PORT', '6379')}`,
      }),
    }),
    PassportModule,
    PrismaModule,
    NodeMailerModule,
    EncryptionModule,
    forwardRef(() => SessionsModule),
  ],
  controllers: [AuthController],
  providers: [AuthService, GoogleStrategy],
  exports: [AuthService, JwtModule],
})
export class AuthModule {}
