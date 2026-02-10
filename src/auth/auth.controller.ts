import { Body, Controller, Get, Post, Query } from '@nestjs/common';
import { AuthService } from './auth.service';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Post("register")
    async register(@Body() data: { name: string; email: string; password: string }) {
        return this.authService.register(data)
    }

    @Post("login")
    async login(@Body() data: { email: string; password: string }) {
        return this.authService.login(data)
    }

    @Post('forget-password')
    forgetPassword(@Body('email') email: string) {
        return this.authService.forgetPassword(email)
    }

    @Post('reset-password')
    resetPassword(
        @Body('resetPasswordToken') resetPasswordToken: string,
        @Body('newPassword') newPassword: string,
    ) {
        return this.authService.resetPassword(resetPasswordToken, newPassword);
    }

    @Post('verify-register-otp')
    verifyRegisterOtp(
        @Body('email') email: string,
        @Body('otp') otp: string
    ) {
        return this.authService.verifyRegisterOtp(email, otp);
    }


}
