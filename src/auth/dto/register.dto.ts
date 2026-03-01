import {
  IsEmail,
  IsNotEmpty,
  IsString,
  MinLength,
  MaxLength,
  Matches,
} from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';
import { Match } from '../../common/decorators/match.decorator';

export class RegisterDto {
  @ApiProperty({
    example: 'user@example.com',
    description: 'Valid email address',
  })
  @IsEmail()
  email: string;

  @ApiProperty({
    example: 'Password123',
    description:
      'Password must be 8-32 characters and contain uppercase, lowercase and number',
    minLength: 8,
    maxLength: 32,
  })
  @IsString()
  @MinLength(8)
  @MaxLength(32)
  @Matches(/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).+$/, {
    message: 'Password must contain uppercase, lowercase and number',
  })
  password: string;

  @ApiProperty({
    example: 'Password123',
    description: 'Must match the password field',
    minLength: 8,
    maxLength: 32,
  })
  @IsString()
  @MinLength(8)
  @MaxLength(32)
  @Match('password', {
    message: 'Password confirmation must match password',
  })
  confirmPassword: string;

  @ApiProperty({
    example: 'john_doe',
    description: 'Username must be 3-20 characters',
    minLength: 3,
    maxLength: 20,
  })
  @IsString()
  @IsNotEmpty()
  @MinLength(3)
  @MaxLength(20)
  username: string;
}