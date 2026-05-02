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
import {
  ApiBearerAuth,
  ApiBody,
  ApiConsumes,
  ApiOperation,
  ApiTags,
} from '@nestjs/swagger';
import { UserSettingsService } from './user-settings.service';
import { TokenGuard } from 'src/auth/guards/auth.guard';
import { EditProfileDto } from './dto/edit-profile.dto';
import { ChangePasswordDto } from './dto/change-password.dto';
import { ThemeModeDto } from './dto/theme-mode.dto';
import { UpdateNotificationsDto } from './dto/update-notifications.dto';
import { VerifyTotpDto } from './dto/verify-totp.dto';
import { ApiOkWrapped, ApiStandardErrorResponses } from 'src/common/swagger';

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

@ApiTags('user-settings')
@ApiStandardErrorResponses()
@Controller('user-settings')
@UseGuards(TokenGuard)
@ApiBearerAuth()
export class UserSettingsController {
  constructor(private readonly userSettingsService: UserSettingsService) {}

  @Get()
  @ApiOperation({ summary: 'Get user settings bundle' })
  @ApiOkWrapped('Settings object', { themeMode: 'system', notifications: true })
  getSettings(@Req() req: { user: { id: number } }) {
    return this.userSettingsService.getSettings(req.user.id);
  }

  @Patch('profile')
  @ApiOperation({ summary: 'Update profile; optional avatar (multipart)' })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    schema: {
      type: 'object',
      properties: {
        username: { type: 'string', example: 'new_name' },
        avatar: { type: 'string', format: 'binary', description: 'JPEG/PNG/GIF/WebP, max 5MB' },
      },
    },
  })
  @ApiOkWrapped('Updated profile', { username: 'new_name', avatar: 'https://...' })
  @UseInterceptors(FileInterceptor('avatar', avatarUpload))
  editProfile(
    @Req() req: { user: { id: number } },
    @Body() dto: EditProfileDto,
    @UploadedFile() file?: Express.Multer.File,
  ) {
    return this.userSettingsService.editProfile(req.user.id, dto, file);
  }

  @Patch('password')
  @ApiOperation({ summary: 'Change password' })
  @ApiBody({ type: ChangePasswordDto })
  @ApiOkWrapped('Password changed', { message: 'ok' })
  changePassword(
    @Req() req: { user: { id: number } },
    @Body() dto: ChangePasswordDto,
  ) {
    return this.userSettingsService.changePassword(req.user.id, dto);
  }

  @Patch('theme')
  @ApiOperation({ summary: 'Set theme mode' })
  @ApiBody({ type: ThemeModeDto })
  @ApiOkWrapped('Theme updated', { themeMode: 'dark' })
  updateThemeMode(
    @Req() req: { user: { id: number } },
    @Body() dto: ThemeModeDto,
  ) {
    return this.userSettingsService.updateThemeMode(req.user.id, dto.themeMode);
  }

  @Patch('notifications')
  @ApiOperation({ summary: 'Set push notifications preference' })
  @ApiBody({ type: UpdateNotificationsDto })
  @ApiOkWrapped('Notifications preference updated', { notificationsEnabled: false })
  updateNotificationsEnabled(
    @Req() req: { user: { id: number } },
    @Body() dto: UpdateNotificationsDto,
  ) {
    return this.userSettingsService.updateNotificationsEnabled(req.user.id, dto.notificationsEnabled);
  }

  @Post('2fa/setup')
  @ApiOperation({ summary: 'Start 2FA setup (returns secret/QR payload)' })
  @ApiOkWrapped('2FA setup payload', { secret: 'BASE32...', otpauthUrl: 'otpauth://...' })
  setup2FA(@Req() req: { user: { id: number } }) {
    return this.userSettingsService.setup2FA(req.user.id);
  }

  @Post('2fa/enable')
  @ApiOperation({ summary: 'Enable 2FA with TOTP code' })
  @ApiBody({ type: VerifyTotpDto })
  @ApiOkWrapped('2FA enabled', { enabled: true })
  enable2FA(
    @Req() req: { user: { id: number } },
    @Body() dto: VerifyTotpDto,
  ) {
    return this.userSettingsService.enable2FA(req.user.id, dto.code);
  }

  @Post('2fa/disable')
  @ApiOperation({ summary: 'Disable 2FA with TOTP code' })
  @ApiBody({ type: VerifyTotpDto })
  @ApiOkWrapped('2FA disabled', { enabled: false })
  disable2FA(
    @Req() req: { user: { id: number } },
    @Body() dto: VerifyTotpDto,
  ) {
    return this.userSettingsService.disable2FA(req.user.id, dto.code);
  }
}
