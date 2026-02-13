import { Body, Controller, Get, Header, Headers, Post, Query, Req, Res, UseGuards } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthGuard } from '@nestjs/passport';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { TokenGuard } from './guards/auth.guard';

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
    @UseGuards(TokenGuard)
    @Post("logout")
    async logout(@Headers('authorization') authHeader: string) {
        const token = authHeader?.split(' ')[1];
        return this.authService.logout(token)
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
    @UseGuards(TokenGuard)
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
