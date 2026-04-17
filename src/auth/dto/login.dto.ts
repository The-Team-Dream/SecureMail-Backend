import { IsEmail, IsString, Matches, MaxLength, MinLength } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class LoginDto {
    @ApiProperty({
        example: 'user@example.com',
        description: 'Registered email address',
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
}
