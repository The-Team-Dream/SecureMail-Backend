import {
  BadRequestException,
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma.service';
import * as bcrypt from 'bcrypt';
import { ThemeMode, NotificationType } from '@prisma/client';
import { EditProfileDto } from './dto/edit-profile.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ThemeModeDto } from './dto/theme-mode.dto';
import { UpdateNotificationsDto } from './dto/update-notifications.dto';
import { StorageService } from './storage.service';
import { NotificationsService } from '../notifications/notifications.service';
import { generateSecret, generateURI, verifySync } from 'otplib';
import * as QRCode from 'qrcode';

@Injectable()
export class UserSettingsService {
  constructor(
    private prisma: PrismaService,
    private storage: StorageService,
    private notificationsService: NotificationsService,
  ) {}

  async getSettings(userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        username: true,
        email: true,
        avatar: true,
        totpEnabled: true,
        provider: true,
      },
    });
    if (!user) {
      throw new UnauthorizedException('User not found');
    }

    const settings = await this.prisma.userSetting.findUnique({
      where: { userId },
    });

    return {
      user: {
        ...user,
        avatar: user.avatar 
          ? (user.avatar.startsWith('http') ? user.avatar : `/uploads/${user.avatar}`) 
          : null,
      },
      settings: settings
        ? {
            themeMode: settings.themeMode,
            notificationsEnabled: settings.notificationsEnabled,
          }
        : {
            themeMode: ThemeMode.LIGHT,
            notificationsEnabled: true,
          },
    };
  }

  async editProfile(userId: number, dto: EditProfileDto, file?: Express.Multer.File) {
    const updateData: { username?: string; avatar?: string } = {};

    if (dto.username !== undefined) {
      updateData.username = dto.username;
    }

    if (file) {
      this.storage.validateFile(file.mimetype, file.size);
      const user = await this.prisma.user.findUnique({
        where: { id: userId },
        select: { avatar: true },
      });
      if (user?.avatar) {
        await this.storage.deleteFile(user.avatar);
      }
      const path = await this.storage.saveFile(file.buffer, file.mimetype, userId);
      updateData.avatar = path;
    }

    if (Object.keys(updateData).length === 0) {
      throw new BadRequestException('No valid fields to update');
    }

    const updated = await this.prisma.user.update({
      where: { id: userId },
      data: updateData,
      select: {
        id: true,
        username: true,
        email: true,
        avatar: true,
      },
    });

    return {
      ...updated,
      avatar: updated.avatar 
        ? (updated.avatar.startsWith('http') ? updated.avatar : `/uploads/${updated.avatar}`) 
        : null,
    };
  }

  async changePassword(userId: number, dto: ChangePasswordDto) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { passwordHash: true, provider: true },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }
    if (user.provider !== 'local' || !user.passwordHash) {
      throw new BadRequestException('Password cannot be changed for OAuth accounts');
    }

    const valid = await bcrypt.compare(dto.currentPassword, user.passwordHash);
    if (!valid) {
      throw new UnauthorizedException('Current password is incorrect');
    }

    const hashedPassword = await bcrypt.hash(dto.newPassword, 10);
    await this.prisma.user.update({
      where: { id: userId },
      data: { passwordHash: hashedPassword },
    });

    try {
      await this.notificationsService.create({
        userId,
        type: NotificationType.PASSWORD_CHANGED,
        title: 'Password Changed',
        message: 'Your password has been successfully changed.',
        metadata: { changedAt: new Date().toISOString() },
      });
    } catch {
      // Notification failure is non-fatal
    }

    return { message: 'Password updated successfully' };
  }

  async updateThemeMode(userId: number, themeMode: ThemeMode) {
    await this.prisma.userSetting.upsert({
      where: { userId },
      create: {
        userId,
        themeMode,
        notificationsEnabled: true,
      },
      update: { themeMode },
    });

    return { themeMode };
  }

  async updateNotificationsEnabled(userId: number, notificationsEnabled: boolean) {
    await this.prisma.userSetting.upsert({
      where: { userId },
      create: {
        userId,
        themeMode: ThemeMode.LIGHT,
        notificationsEnabled,
      },
      update: { notificationsEnabled },
    });

    return { notificationsEnabled };
  }

  async setup2FA(userId: number) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { email: true, totpEnabled: true, totpSecret: true },
    });

    if (!user) {
      throw new UnauthorizedException('User not found');
    }
    if (user.totpEnabled) {
      throw new ConflictException('2FA is already enabled');
    }

    const secret = generateSecret();
    const otpauthUrl = generateURI({
      issuer: 'SecureMail',
      label: user.email,
      secret,
    });

    await this.prisma.user.update({
      where: { id: userId },
      data: { totpSecret: secret },
    });

    const qrCodeDataUrl = await QRCode.toDataURL(otpauthUrl);

    return {
      secret,
      qrCode: qrCodeDataUrl,
      message: 'Scan the QR code with your authenticator app, then verify with the code',
    };
  }

  async enable2FA(userId: number, code: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { totpSecret: true, totpEnabled: true },
    });

    if (!user?.totpSecret) {
      throw new BadRequestException('2FA setup not initiated. Call setup2FA first.');
    }
    if (user.totpEnabled) {
      throw new ConflictException('2FA is already enabled');
    }

    const result = verifySync({ secret: user.totpSecret, token: code });
    if (!result.valid) {
      throw new UnauthorizedException('Invalid TOTP code');
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: { totpEnabled: true },
    });

    return { message: '2FA enabled successfully' };
  }

  async disable2FA(userId: number, code: string) {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { totpSecret: true, totpEnabled: true },
    });

    if (!user?.totpSecret || !user.totpEnabled) {
      throw new BadRequestException('2FA is not enabled');
    }

    const result = verifySync({ secret: user.totpSecret, token: code });
    if (!result.valid) {
      throw new UnauthorizedException('Invalid TOTP code');
    }

    await this.prisma.user.update({
      where: { id: userId },
      data: { totpSecret: null, totpEnabled: false },
    });

    return { message: '2FA disabled successfully' };
  }

  async verify2FALogin(userId: number, code: string): Promise<boolean> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: { totpSecret: true, totpEnabled: true },
    });
    if (!user?.totpEnabled || !user.totpSecret) return true;
    const result = verifySync({ secret: user.totpSecret, token: code });
    return result.valid;
  }
}
