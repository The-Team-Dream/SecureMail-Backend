import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsArray,
  IsEmail,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';

export class ForwardEmailDto {
  @ApiProperty({ description: 'Recipient email address', example: 'recipient@example.com' })
  @IsEmail()
  to: string;

  @ApiPropertyOptional({ description: 'Additional message to include' })
  @IsOptional()
  @IsString()
  @MaxLength(50000)
  message?: string;
}
