import {
    Body,
    Controller,
    Get,
    Headers,
    Post,
    Query,
    Req,
    Res,
    UnauthorizedException,
    UseGuards,
} from '@nestjs/common';
import {
    ApiBearerAuth,
    ApiBody,
    ApiHeader,
    ApiOperation,
    ApiResponse,
    ApiTags,
    ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { AuthService } from './auth.service';
import { AuthGuard } from '@nestjs/passport';
import { RegisterDto } from './dto/register.dto';
import { GoogleMobileLoginDto } from './dto/google-mobile-login.dto';
import { LoginDto } from './dto/login.dto';
import { ForgetPasswordDto } from './dto/forgetpassword.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { ResendOtpDto } from './dto/resend-otp.dto';
import { Verify2FADto } from './dto/verify-2fa.dto';
import { TokenGuard } from './guards/auth.guard';
import { ApiOkWrapped, ApiStandardErrorResponses } from 'src/common/swagger';
import { ApiErrorResponseDto } from 'src/common/swagger/api-error-response.dto';
import { Public } from './decorators/public.decorator';

@ApiTags('auth')
@ApiStandardErrorResponses()
@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) { }

    @Post('register')
    @ApiOperation({ summary: 'Register a new local account' })
    @ApiBody({ type: RegisterDto })
    @ApiResponse({
        status: 201,
        description: 'Registration started; OTP email sent',
        schema: {
            example: {
                success: true,
                message: 'Request successful',
                data: { message: 'OTP sent to your email' },
            },
        },
    })
    async register(@Body() data: RegisterDto) {
        return this.authService.register(data);
    }

    @Post('login')
    @ApiOperation({
        summary: 'Login with email and password',
        description:
            'Returns JWT `token`, or `requires2FA` + `tempToken` when 2FA is enabled (use POST /auth/verify-2fa).',
    })
    @ApiBody({ type: LoginDto })
    @ApiResponse({
        status: 200,
        description: 'Logged in, or 2FA required',
        schema: {
            oneOf: [
                {
                    example: {
                        success: true,
                        message: 'Request successful',
                        data: { token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...' },
                    },
                },
                {
                    example: {
                        success: true,
                        message: 'Request successful',
                        data: {
                            requires2FA: true,
                            tempToken: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
                        },
                    },
                },
            ],
        },
    })
    @ApiUnauthorizedResponse({ description: 'Invalid credentials', type: ApiErrorResponseDto })
    async login(
        @Body() data: LoginDto,
        @Req()
        req: {
            ip?: string;
            headers: { 'user-agent'?: string; 'x-forwarded-for'?: string };
        },
    ) {
        const forwarded = req.headers['x-forwarded-for'];
        const ip =
            req.ip ??
            (typeof forwarded === 'string' ? forwarded.split(',')[0]?.trim() : forwarded?.[0]) ??
            'unknown';
        const sessionContext = {
            ipAddress: ip,
            userAgent: req.headers['user-agent'] ?? '',
        };
        return this.authService.login(data, sessionContext);
    }

    @Post('verify-2fa')
    @ApiOperation({
        summary: 'Complete login after 2FA',
        description: 'Authorization: Bearer <tempToken> from login response.',
    })
    @ApiHeader({
        name: 'Authorization',
        required: true,
        example: 'Bearer <tempToken>',
    })
    @ApiBody({ type: Verify2FADto })
    @ApiOkWrapped('JWT issued', {
        token: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
    })
    @ApiUnauthorizedResponse({ description: 'Missing/invalid temp token or bad TOTP', type: ApiErrorResponseDto })
    async verify2FA(
        @Headers('authorization') authHeader: string,
        @Body() data: Verify2FADto,
        @Req()
        req: {
            ip?: string;
            headers: { 'user-agent'?: string; 'x-forwarded-for'?: string };
        },
    ) {
        const tempToken = authHeader?.replace(/^Bearer\s+/i, '').trim();
        if (!tempToken) {
            throw new UnauthorizedException('Temp token required');
        }
        const forwarded = req.headers['x-forwarded-for'];
        const ip =
            req.ip ??
            (typeof forwarded === 'string' ? forwarded.split(',')[0]?.trim() : forwarded?.[0]) ??
            'unknown';
        const sessionContext = {
            ipAddress: ip,
            userAgent: req.headers['user-agent'] ?? '',
        };
        return this.authService.verify2FA(tempToken, data.code, sessionContext);
    }

    @UseGuards(TokenGuard)
    @Post('logout')
    @ApiBearerAuth()
    @ApiOperation({ summary: 'Invalidate current session / token' })
    @ApiOkWrapped('Logged out', { message: 'Logout successfully' })
    async logout(@Headers('authorization') authHeader: string) {
        const token = authHeader?.split(' ')[1];
        return this.authService.logout(token);
    }

    @Post('forget-password')
    @ApiOperation({ summary: 'Request password reset email' })
    @ApiBody({ type: ForgetPasswordDto })
    @ApiOkWrapped('Acknowledgement (email may or may not exist)', {
        message: 'If email exists, reset link will be sent',
    })
    forgetPassword(@Body() data: ForgetPasswordDto) {
        return this.authService.forgetPassword(data.email, data.clientType);
    }

    @Post('reset-password')
    @ApiOperation({ summary: 'Set new password using reset token' })
    @ApiBody({ type: ResetPasswordDto })
    @ApiOkWrapped('Password updated', { message: 'Password updated successfully' })
    resetPassword(@Body() data: ResetPasswordDto) {
        return this.authService.resetPassword(data);
    }

    @Post('verify-register-otp')
    @ApiOperation({ summary: 'Verify registration OTP' })
    @ApiBody({ type: VerifyOtpDto })
    @ApiOkWrapped('Account verified', { message: 'Account verified successfully' })
    verifyRegisterOtp(@Body() data: VerifyOtpDto) {
        return this.authService.verifyRegisterOtp(data.email, data.otp);
    }

    @Post('resend-otp')
    @ApiOperation({
        summary: 'Resend registration OTP',
        description:
            'Re-sends the 6-digit verification OTP to the email address. ' +
            'Rate-limited to once per 60 seconds per address. ' +
            'Always returns the same response regardless of whether the email exists.',
    })
    @ApiBody({ type: ResendOtpDto })
    @ApiOkWrapped('OTP resent (or silently dropped if address not pending)', {
        message: 'If your account is pending verification, a new OTP has been sent.',
    })
    resendOtp(@Body() data: ResendOtpDto) {
        return this.authService.resendOtp(data.email);
    }

    @Get('google/login')
    @UseGuards(AuthGuard('google'))
    @ApiOperation({
        summary: 'Start Google OAuth',
        description: 'Standard web-based redirect flow.',
    })
    googleLogin() { }

    @Post('google/mobile')
    @ApiOperation({ summary: 'Google Sign-In for Mobile' })
    async googleMobileLogin(
        @Body() body: GoogleMobileLoginDto,
        @Req() req: any,
    ) {
        const forwarded = req.headers['x-forwarded-for'];
        const ip = req.ip ?? (typeof forwarded === 'string' ? forwarded.split(',')[0]?.trim() : forwarded?.[0]) ?? 'unknown';
        const sessionContext = {
            ipAddress: ip,
            userAgent: req.headers['user-agent'] ?? 'mobile-app',
        };

        return this.authService.googleLoginMobile(body.idToken, sessionContext);
    }

    @Get('google/callback')
    @UseGuards(AuthGuard('google'))
    @ApiOperation({ summary: 'Google OAuth callback (redirect)' })
    @ApiResponse({ status: 302, description: 'Redirect to frontend with token query param' })
    async googleCallback(
        @Req() req: any,
        @Res() res: any,
        @Query('state') state?: string,
    ) {
        const forwarded = req.headers['x-forwarded-for'];
        const ip =
            req.ip ??
            (typeof forwarded === 'string' ? forwarded.split(',')[0]?.trim() : forwarded?.[0]) ??
            'unknown';
        const sessionContext = {
            ipAddress: ip,
            userAgent: req.headers['user-agent'] ?? '',
        };

        const decodedState = this.parseState(state);
        const clientType = decodedState?.clientType ?? 'web';

        const token = await this.authService.generateJWT(req.user, sessionContext);

        if (clientType === 'mobile') {
            return res.redirect(`securemail://app/oauth-success?token=${token}`);
        }

        const base = process.env.FRONTEND_URL ?? 'http://localhost:3001';
        return res.redirect(`${base}/oauth-success?token=${token}`);
    }

    @Public()
    @Get('redirect')
    @ApiOperation({ summary: 'Deep link bridge for email clients' })
    async deepLinkRedirect(
        @Query('url') url: string,
        @Res() res: any,
    ) {
        // التحويل من رابط HTTPS إلى رابط التطبيق (Deep Link)
        // الإيميلات بتقبل HTTPS بس، فإحنا بنخليهم يضغطوا على ده والباكند يحولهم للتطبيق
        return res.redirect(url);
    }

    private parseState(state?: string): Record<string, any> | null {
        if (!state) return null;
        try {
            const jsonStr = Buffer.from(state, 'base64url').toString();
            return JSON.parse(jsonStr);
        } catch {
            return null;
        }
    }
}
