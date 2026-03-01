import { ApiProperty } from '@nestjs/swagger';
import { IsEnum } from 'class-validator';

export enum TargetFolderType {
  INBOX = 'inbox',
  SENT = 'sent',
  SPAM = 'spam',
  PHISHING = 'phishing',
  TRASH = 'trash',
}

export class ReclassifyEmailDto {
  @ApiProperty({
    description: 'Target folder to move the email to',
    enum: TargetFolderType,
    example: TargetFolderType.INBOX,
  })
  @IsEnum(TargetFolderType)
  folder: TargetFolderType;
}
