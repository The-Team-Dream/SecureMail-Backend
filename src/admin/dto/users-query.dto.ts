import { ApiPropertyOptional } from '@nestjs/swagger';
import { IsBoolean, IsOptional, IsString } from 'class-validator';
import { Type } from 'class-transformer';
import { AdminPaginatedDto } from './common.dto';

export class AdminUsersQueryDto extends AdminPaginatedDto {
  @ApiPropertyOptional({ description: 'Search by name or email' })
  @IsOptional()
  @IsString()
  search?: string;

  @ApiPropertyOptional({ description: 'Filter by active (not banned/deleted)' })
  @IsOptional()
  @Type(() => Boolean)
  @IsBoolean()
  active?: boolean;

  @ApiPropertyOptional({ description: 'Filter by banned' })
  @IsOptional()
  @Type(() => Boolean)
  @IsBoolean()
  banned?: boolean;
}
