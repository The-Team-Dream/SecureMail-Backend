import { Module } from '@nestjs/common';
import { AuthController } from './auth.controller';
import { AuthService } from './auth.service';
import { PrismaModule } from 'src/prisma.module';
import { JwtModule } from '@nestjs/jwt';
import { NodeMailerModule } from 'src/node-mailer/node-mailer.module';
import { PassportModule } from '@nestjs/passport';
import { GoogleStrategy } from './strategies/google-strategy';

@Module({
  imports: [
    JwtModule.register({
      global: true,
      secret: "secret",
      signOptions: { expiresIn: '60s' },
    }),
    PassportModule,
    PrismaModule,
    NodeMailerModule
  ],
  controllers: [AuthController],
  providers: [AuthService, GoogleStrategy]
})
export class AuthModule { }
