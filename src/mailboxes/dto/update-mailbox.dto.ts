import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean, IsOptional, IsString, MaxLength, MinLength } from 'class-validator';

export class UpdateMailboxDto {
  @ApiProperty({
    description: 'Display name for the mailbox',
    example: 'My Gmail',
    required: false,
  })
  @IsOptional()
  @IsString()
  @MinLength(1)
  @MaxLength(100)
  displayName?: string;

  @ApiProperty({
    description: 'Enable push notifications for new emails',
    example: true,
    required: false,
  })
  @IsOptional()
  @IsBoolean()
  pushNotificationsEnabled?: boolean;
}
