import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsIn, IsOptional } from 'class-validator';

export class ActivityPeriodDto {
  @ApiPropertyOptional({
    description: 'Time period for activity data',
    enum: ['daily', 'weekly', 'monthly'],
    default: 'daily',
  })
  @IsOptional()
  @IsIn(['daily', 'weekly', 'monthly'])
  period?: 'daily' | 'weekly' | 'monthly' = 'daily';
}
