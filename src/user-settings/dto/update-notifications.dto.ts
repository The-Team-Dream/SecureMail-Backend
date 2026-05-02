import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean } from 'class-validator';

export class UpdateNotificationsDto {
  @ApiProperty({
    example: false,
    description: 'Whether to receive push notifications for new emails and security events.',
  })
  @IsBoolean()
  notificationsEnabled!: boolean;
}
