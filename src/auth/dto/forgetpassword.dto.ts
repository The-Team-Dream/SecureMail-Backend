import { ApiProperty } from '@nestjs/swagger';
import { IsEmail, IsIn, IsOptional } from 'class-validator';

export class ForgetPasswordDto {
    @ApiProperty({
        example: 'user@example.com',
        description: 'Account email to send password reset to',
    })
    @IsEmail()
    email!: string;

    @ApiProperty({
        example: 'web',
        description: 'Type of client making the request',
        enum: ['web', 'mobile'],
        required: false,
    })
    @IsOptional()
    @IsIn(['web', 'mobile'])
    clientType?: 'web' | 'mobile' = 'web';
}
