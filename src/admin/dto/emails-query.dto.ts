import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsEnum, IsInt, IsOptional, IsString, Min } from 'class-validator';
import { Type } from 'class-transformer';
import { AdminPaginatedDto } from './common.dto';

export enum AdminEmailClassification {
  INBOX = 'inbox',
  SPAM = 'spam',
  PHISHING = 'phishing',
}

export class AdminEmailsQueryDto extends AdminPaginatedDto {
  @ApiPropertyOptional({ enum: AdminEmailClassification })
  @IsOptional()
  @IsEnum(AdminEmailClassification)
  classification?: AdminEmailClassification;

  @ApiPropertyOptional({ description: 'Filter from date (ISO)' })
  @IsOptional()
  @IsString()
  fromDate?: string;

  @ApiPropertyOptional({ description: 'Filter to date (ISO)' })
  @IsOptional()
  @IsString()
  toDate?: string;

  @ApiPropertyOptional({ description: 'Filter by mailbox ID' })
  @IsOptional()
  @Type(() => Number)
  @IsInt()
  @Min(1)
  mailboxId?: number;

  @ApiPropertyOptional({ description: 'Search by subject or sender' })
  @IsOptional()
  @IsString()
  search?: string;
}
