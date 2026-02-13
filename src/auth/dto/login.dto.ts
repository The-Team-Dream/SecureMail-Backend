import { IsEmail, IsString, Matches, MaxLength, MinLength } from 'class-validator';

export class LoginDto {

    @IsEmail()
    email: string;

    @IsString()
    @MinLength(8)
    @MaxLength(32)
    @Matches(/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d).+$/, {
        message: 'Password must contain uppercase, lowercase and number'
    })
    password: string;
}
