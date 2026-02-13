import { Body, Controller, Get, Post, Query, Req, Res, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthGuard } from '@nestjs/passport';
import { Response } from 'express';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Post("register")
    async register(@Body() data: RegisterDto) {
        return this.authService.register(data)
    }

    @Post("login")
    async login(@Body() data: LoginDto) {
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

    @Get('google/login')
    @UseGuards(AuthGuard('google'))
    googleLogin() { }

    @Get('google/callback')
    @UseGuards(AuthGuard('google'))
    async googleCallback(@Req() req, @Res() res) {
        const token = await this.authService.generateJWT(req.user)
        return res.redirect(`http://localhost:3001/oauth-success?token=${token}`)
    }
}
