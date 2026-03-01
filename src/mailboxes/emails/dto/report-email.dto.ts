import { ApiProperty } from '@nestjs/swagger';
import { IsEnum } from 'class-validator';

export enum ReportType {
  SPAM = 'spam',
  PHISHING = 'phishing',
}

export class ReportEmailDto {
  @ApiProperty({
    description: 'Type of report',
    enum: ReportType,
    example: ReportType.SPAM,
  })
  @IsEnum(ReportType)
  type: ReportType;
}
