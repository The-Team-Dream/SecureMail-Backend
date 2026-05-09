import { ApiProperty } from '@nestjs/swagger';
import { IsBoolean } from 'class-validator';

export class ToggleStarDto {
  @ApiProperty({ description: 'Whether the email should be starred (flagged)', example: true })
  @IsBoolean()
  starred: boolean;
}
