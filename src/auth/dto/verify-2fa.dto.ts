import { IsNotEmpty, IsString, Length, Matches } from 'class-validator';

export class Verify2FADto {
  @IsString()
  @IsNotEmpty({ message: 'TOTP code is required' })
  @Length(6, 6, { message: 'TOTP code must be exactly 6 digits' })
  @Matches(/^\d{6}$/, { message: 'TOTP code must contain only digits' })
  code: string;
}
