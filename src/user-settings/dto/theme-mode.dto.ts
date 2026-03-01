import { IsEnum } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { ThemeMode } from 'generated/prisma/client';

export class ThemeModeDto {
  @ApiProperty({
    example: ThemeMode.LIGHT,
    description: 'Theme mode preference',
    enum: ThemeMode,
  })
  @IsEnum(ThemeMode, {
    message: 'Theme mode must be either LIGHT or DARK',
  })
  themeMode: ThemeMode;
}