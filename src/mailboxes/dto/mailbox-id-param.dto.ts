import { ApiProperty } from '@nestjs/swagger';
import { IsInt, Min } from 'class-validator';
import { Type } from 'class-transformer';

export class MailboxIdParamDto {
  @ApiProperty({ description: 'Mailbox ID', example: 1 })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  id: number;
}
