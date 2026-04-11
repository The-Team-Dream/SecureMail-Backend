import { ApiProperty } from '@nestjs/swagger';
import { IsEmail } from 'class-validator';

export class ForgetPasswordDto {
    @ApiProperty({
        example: 'user@example.com',
        description: 'Account email to send password reset to',
    })
    @IsEmail()
    email!: string;
}
