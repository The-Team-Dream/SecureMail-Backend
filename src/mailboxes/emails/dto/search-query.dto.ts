import { ApiProperty } from '@nestjs/swagger';
import { IsOptional, IsString } from 'class-validator';
import { PaginatedQueryDto } from './paginated-query.dto';

export class SearchQueryDto extends PaginatedQueryDto {
  @ApiProperty({
    required: false,
    description: 'Text to search in subject, fromAddr, or fromName',
    example: 'invoice',
  })
  @IsOptional()
  @IsString()
  q?: string;
}
