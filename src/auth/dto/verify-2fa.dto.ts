import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, Length, Matches } from 'class-validator';

export class Verify2FADto {
    @ApiProperty({
        example: '123456',
        description: '6-digit TOTP from authenticator app',
        minLength: 6,
        maxLength: 6,
    })
    @IsString()
    @IsNotEmpty({ message: 'TOTP code is required' })
    @Length(6, 6, { message: 'TOTP code must be exactly 6 digits' })
    @Matches(/^\d{6}$/, { message: 'TOTP code must contain only digits' })
    code!: string;
}
