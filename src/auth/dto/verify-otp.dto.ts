import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsString, Length, Matches } from 'class-validator';

export class VerifyOtpDto {
    @ApiProperty({ example: 'user@example.com' })
    @IsEmail()
    email!: string;

    @ApiProperty({
        example: '482910',
        description: '6-digit OTP from registration email',
        minLength: 6,
        maxLength: 6,
    })
    @IsString()
    @Length(6, 6)
    @Matches(/^\d+$/, { message: 'OTP must be numeric' })
    otp!: string;
}
