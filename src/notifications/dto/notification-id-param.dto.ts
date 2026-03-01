import { ApiProperty } from '@nestjs/swagger';
import { IsInt, Min } from 'class-validator';
import { Type } from 'class-transformer';

export class NotificationIdParamDto {
  @ApiProperty({ description: 'Notification ID' })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  id: number;
}
