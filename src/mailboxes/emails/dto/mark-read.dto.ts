import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean } from 'class-validator';

export class MarkReadDto {
  @ApiProperty({ description: 'Whether the email should be marked as read', example: true })
  @IsBoolean()
  read: boolean;
}
