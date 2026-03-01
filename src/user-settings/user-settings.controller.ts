import {
  Body,
  Controller,
  Get,
  Patch,
  Post,
  Req,
  UploadedFile,
  UseGuards,
  UseInterceptors,
} from '@nestjs/common';
import { FileInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import { UserSettingsService } from './user-settings.service';
import { TokenGuard } from 'src/auth/guards/auth.guard';
import { EditProfileDto } from './dto/edit-profile.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ThemeModeDto } from './dto/theme-mode.dto';
import { VerifyTotpDto } from './dto/verify-totp.dto';

const avatarUpload = {
  storage: memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (_req: unknown, file: Express.Multer.File, cb: (err: Error | null, acceptFile: boolean) => void) => {
    const allowed = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
    if (allowed.includes(file.mimetype)) {
      cb(null, true);
    } else {
      cb(new Error('Invalid file type. Allowed: JPEG, PNG, GIF, WebP'), false);
    }
  },
};

@Controller('user-settings')
@UseGuards(TokenGuard)
export class UserSettingsController {
  constructor(private readonly userSettingsService: UserSettingsService) {}

  @Get()
  getSettings(@Req() req: { user: { id: number } }) {
    return this.userSettingsService.getSettings(req.user.id);
  }

  @Patch('profile')
  @UseInterceptors(FileInterceptor('avatar', avatarUpload))
  editProfile(
    @Req() req: { user: { id: number } },
    @Body() dto: EditProfileDto,
    @UploadedFile() file?: Express.Multer.File,
  ) {
    return this.userSettingsService.editProfile(req.user.id, dto, file);
  }

  @Patch('password')
  changePassword(
    @Req() req: { user: { id: number } },
    @Body() dto: ChangePasswordDto,
  ) {
    return this.userSettingsService.changePassword(req.user.id, dto);
  }

  @Patch('theme')
  updateThemeMode(
    @Req() req: { user: { id: number } },
    @Body() dto: ThemeModeDto,
  ) {
    return this.userSettingsService.updateThemeMode(req.user.id, dto.themeMode);
  }

  @Post('2fa/setup')
  setup2FA(@Req() req: { user: { id: number } }) {
    return this.userSettingsService.setup2FA(req.user.id);
  }

  @Post('2fa/enable')
  enable2FA(
    @Req() req: { user: { id: number } },
    @Body() dto: VerifyTotpDto,
  ) {
    return this.userSettingsService.enable2FA(req.user.id, dto.code);
  }

  @Post('2fa/disable')
  disable2FA(
    @Req() req: { user: { id: number } },
    @Body() dto: VerifyTotpDto,
  ) {
    return this.userSettingsService.disable2FA(req.user.id, dto.code);
  }
}
