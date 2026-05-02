import {
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';
import { ApiPropertyOptional } from '@nestjs/swagger';

export class EditProfileDto {
  @ApiPropertyOptional({
    example: 'john_doe',
    description: 'New username (2-50 characters)',
    minLength: 2,
    maxLength: 50,
  })
  @IsOptional()
  @IsString()
  @MinLength(2, { message: 'Name must be at least 2 characters' })
  @MaxLength(50, { message: 'Name must not exceed 50 characters' })
  username?: string;

  @ApiPropertyOptional({
    example: true,
    description: 'If true, the current avatar will be removed. Ignored if a new avatar file is uploaded.',
  })
  @IsOptional()
  removeAvatar?: boolean;
}
