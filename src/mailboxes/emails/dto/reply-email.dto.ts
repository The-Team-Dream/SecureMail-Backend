import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsOptional, IsString, MaxLength, MinLength } from 'class-validator';

export class ReplyEmailDto {
  @ApiProperty({ description: 'Reply content (plain text)', example: 'Thanks for your email!' })
  @IsString()
  @MinLength(1)
  @MaxLength(50000)
  content: string;

  @ApiPropertyOptional({ description: 'HTML body (overrides content if provided)' })
  @IsOptional()
  @IsString()
  @MaxLength(50000)
  bodyHtml?: string;
}
