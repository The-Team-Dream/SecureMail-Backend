import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsArray,
  IsEmail,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';
import { Transform } from 'class-transformer';

function parseEmailArray(val: unknown): string[] | undefined {
  if (Array.isArray(val)) return val.filter((v) => typeof v === 'string');
  if (typeof val === 'string') {
    if (val.startsWith('[')) {
      try {
        const parsed = JSON.parse(val) as unknown;
        return Array.isArray(parsed) ? parsed.filter((v) => typeof v === 'string') : val.split(',').map((s) => s.trim()).filter(Boolean);
      } catch {
        return val.split(',').map((s) => s.trim()).filter(Boolean);
      }
    }
    return val.split(',').map((s) => s.trim()).filter(Boolean);
  }
  return undefined;
}

export class SendEmailDto {
  @ApiProperty({ description: 'Recipient email address', example: 'recipient@example.com' })
  @IsEmail()
  to: string;

  @ApiPropertyOptional({ description: 'CC recipients (comma-separated or JSON array)', type: [String] })
  @IsOptional()
  @Transform(({ value }) => parseEmailArray(value))
  @IsArray()
  @IsEmail({}, { each: true })
  cc?: string[];

  @ApiPropertyOptional({ description: 'BCC recipients (comma-separated or JSON array)', type: [String] })
  @IsOptional()
  @Transform(({ value }) => parseEmailArray(value))
  @IsArray()
  @IsEmail({}, { each: true })
  bcc?: string[];

  @ApiProperty({ description: 'Email subject', example: 'Hello' })
  @IsString()
  @MinLength(1)
  @MaxLength(500)
  subject: string;

  @ApiPropertyOptional({ description: 'Plain text body' })
  @IsOptional()
  @IsString()
  bodyText?: string;

  @ApiPropertyOptional({ description: 'HTML body' })
  @IsOptional()
  @IsString()
  bodyHtml?: string;
}
