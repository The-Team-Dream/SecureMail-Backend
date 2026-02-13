import { IsString, MinLength, Matches } from 'class-validator';

export class ResetPasswordDto {

  @IsString()
  token: string;

  @IsString()
  @MinLength(8)
  @Matches(/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).+$/, {
    message: 'Password must contain uppercase, lowercase and number'
  })
  newPassword: string;
}
