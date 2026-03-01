import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import {
  IsBoolean,
  IsEmail,
  IsInt,
  IsNotEmpty,
  IsOptional,
  IsString,
  Max,
  Min,
} from 'class-validator';
import { Type } from 'class-transformer';

export class ConnectImapDto {
  @ApiProperty({
    description: 'IMAP server host',
    example: 'imap.gmail.com',
  })
  @IsString()
  @IsNotEmpty()
  host: string;

  @ApiProperty({
    description: 'IMAP server port (typically 993 for SSL, 143 for non-SSL)',
    example: 993,
    minimum: 1,
    maximum: 65535,
  })
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(65535)
  port: number;

  @ApiProperty({
    description: 'Email address for authentication',
    example: 'user@example.com',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    description: 'Password or app password for authentication',
  })
  @IsString()
  @IsNotEmpty()
  password: string;

  @ApiProperty({
    description: 'Use SSL/TLS for connection',
    example: true,
    default: true,
  })
  @IsBoolean()
  @IsOptional()
  secure?: boolean = true;

  @ApiProperty({
    description: 'Display name for the mailbox',
    example: 'My Custom Mail',
  })
  @IsString()
  @IsNotEmpty()
  displayName: string;

  @ApiPropertyOptional({
    description: 'SMTP host for sending (defaults inferred from IMAP host if not provided)',
    example: 'smtp.gmail.com',
  })
  @IsOptional()
  @IsString()
  smtpHost?: string;

  @ApiPropertyOptional({
    description: 'SMTP port (typically 587 for TLS, 465 for SSL)',
    example: 587,
  })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  @Max(65535)
  smtpPort?: number;
}
