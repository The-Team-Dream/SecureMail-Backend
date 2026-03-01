import {
    Body,
    Controller,
    Get,
    Headers,
    Post,
    Req,
    Res,
    UnauthorizedException,
    UseGuards,
} from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthGuard } from '@nestjs/passport';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { ForgetPasswordDto } from './dto/forgetpassword.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { Verify2FADto } from './dto/verify-2fa.dto';
import { TokenGuard } from './guards/auth.guard';

@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Post('register')
    async register(@Body() data: RegisterDto) {
        return this.authService.register(data);
    }

    @Post('login')
    async login(@Body() data: LoginDto, @Req() req: { ip?: string; headers: { 'user-agent'?: string; 'x-forwarded-for'?: string } }) {
        const forwarded = req.headers['x-forwarded-for'];
        const ip = req.ip ?? (typeof forwarded === 'string' ? forwarded.split(',')[0]?.trim() : forwarded?.[0]) ?? 'unknown';
        const sessionContext = {
            ipAddress: ip,
            userAgent: req.headers['user-agent'] ?? '',
        };
        return this.authService.login(data, sessionContext); 
    }

    @Post('verify-2fa')
    async verify2FA(
        @Headers('authorization') authHeader: string,
        @Body() data: Verify2FADto,
        @Req() req: { ip?: string; headers: { 'user-agent'?: string; 'x-forwarded-for'?: string } },
    ) {
        const tempToken = authHeader?.replace(/^Bearer\s+/i, '').trim();
        if (!tempToken) {
            throw new UnauthorizedException('Temp token required');
        }
        const forwarded = req.headers['x-forwarded-for'];
        const ip = req.ip ?? (typeof forwarded === 'string' ? forwarded.split(',')[0]?.trim() : forwarded?.[0]) ?? 'unknown';
        const sessionContext = {
            ipAddress: ip,
            userAgent: req.headers['user-agent'] ?? '',
        };
        return this.authService.verify2FA(tempToken, data.code, sessionContext);
    }

    @UseGuards(TokenGuard)
    @Post('logout')
    async logout(@Headers('authorization') authHeader: string) {
        const token = authHeader?.split(' ')[1];
        return this.authService.logout(token);
    }

    @Post('forget-password')
    forgetPassword(@Body() data: ForgetPasswordDto) {
        return this.authService.forgetPassword(data.email);
    }

    @Post('reset-password')
    resetPassword(@Body() data: ResetPasswordDto) {
        return this.authService.resetPassword(
            data.resetPasswordToken,
            data.newPassword,
        );
    }

    @Post('verify-register-otp')
    verifyRegisterOtp(@Body() data: VerifyOtpDto) {
        return this.authService.verifyRegisterOtp(data.email, data.otp);
    }

    @Get('google/login')
    @UseGuards(AuthGuard('google'))
    googleLogin() { }

    @Get('google/callback')
    @UseGuards(AuthGuard('google'))
    async googleCallback(
        @Req() req: { user: { id: number }; ip?: string; headers: { 'user-agent'?: string; 'x-forwarded-for'?: string } },
        @Res() res: { redirect: (url: string) => void },
    ) {
        const forwarded = req.headers['x-forwarded-for'];
        const ip = req.ip ?? (typeof forwarded === 'string' ? forwarded.split(',')[0]?.trim() : forwarded?.[0]) ?? 'unknown';
        const sessionContext = {
            ipAddress: ip,
            userAgent: req.headers['user-agent'] ?? '',
        };
        const token = await this.authService.generateJWT(req.user, sessionContext);
        return res.redirect(`http://localhost:3001/oauth-success?token=${token}`);
    }
}
