import { ApiProperty } from '@nestjs/swagger';
import { IsEmail } from 'class-validator';

export class ResendOtpDto {
    @ApiProperty({
        example: 'user@example.com',
        description: 'Email address of the unverified account',
    })
    @IsEmail()
    email!: string;
}
