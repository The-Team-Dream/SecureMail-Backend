import {
  IsString, IsOptional, IsArray, ValidateNested, IsInt, ArrayMaxSize,
} from 'class-validator';
import { Type } from 'class-transformer';

export class AttachmentDto {
  @IsString()
  filename: string;

  @IsString()
  mimeType: string;
}

// ─── Single Email ─────────────────────────────────────────────────────────────
export class ClassifyEmailDto {
  @IsString()
  subject: string;

  @IsString()
  fromAddr: string;

  @IsOptional() @IsString()
  fromName?: string;

  @IsOptional() @IsString()
  replyTo?: string;

  @IsOptional() @IsString()
  bodyText?: string;

  @IsOptional() @IsString()
  bodyHtml?: string;

  @IsOptional()
  headers?: Record<string, string>;

  @IsOptional() @IsArray() @ValidateNested({ each: true }) @Type(() => AttachmentDto)
  attachments?: AttachmentDto[];

  @IsOptional() @IsInt()
  mailBoxId?: number;
}

// ─── Batch ────────────────────────────────────────────────────────────────────
// FIX: كان ممكن حد يبعت 10,000 email في request واحد ويعمل DB flood
// الـ cap = 100 email per batch request
export class ClassifyBatchDto {
  @IsArray()
  @ArrayMaxSize(100, { message: 'Batch size cannot exceed 100 emails per request' })
  @ValidateNested({ each: true })
  @Type(() => ClassifyEmailDto)
  emails: ClassifyEmailDto[];
}
