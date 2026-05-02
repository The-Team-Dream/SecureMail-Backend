import { ApiProperty } from '@nestjs/swagger';
import {
    IsNotEmpty,
    IsString,
    MinLength,
    MaxLength,
    Matches,
} from 'class-validator';

export class ResetPasswordDto {
    @ApiProperty({
        description: 'Opaque token from reset email',
        example: 'a1b2c3d4e5f6...',
    })
    @IsString()
    @IsNotEmpty()
    resetPasswordToken!: string;

    @ApiProperty({
        example: 'NewPassword123',
        description: 'New password: 8–32 chars, upper, lower, digit',
        minLength: 8,
        maxLength: 32,
    })
    @IsString()
    @MinLength(8)
    @MaxLength(32)
    @Matches(/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).+$/, {
        message: 'Password must contain uppercase, lowercase and number',
    })
    newPassword!: string;

    @ApiProperty({
        example: 'NewPassword123',
        description: 'Confirm your new password',
    })
    @IsString()
    @IsNotEmpty()
    confirmPassword!: string;
}
