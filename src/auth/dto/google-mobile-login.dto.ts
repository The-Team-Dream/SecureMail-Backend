import { IsNotEmpty, IsString } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class GoogleMobileLoginDto {
    @ApiProperty({
        description: 'Google ID Token from mobile client',
        example: 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjRiM...',
    })
    @IsNotEmpty()
    @IsString()
    idToken: string;
}
