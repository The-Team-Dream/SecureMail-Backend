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
import { LoginDto } from './dto/login.dto';
import { ForgetPasswordDto } from './dto/forgetpassword.dto';
import { ResetPasswordDto } from './dto/reset-password.dto';
import { VerifyOtpDto } from './dto/verify-otp.dto';
import { Verify2FADto } from './dto/verify-2fa.dto';
import { TokenGuard } from './guards/auth.guard';
import { ApiOkWrapped, ApiStandardErrorResponses } from 'src/common/swagger';
import { ApiErrorResponseDto } from 'src/common/swagger/api-error-response.dto';

@ApiTags('auth')
@ApiStandardErrorResponses()
@Controller('auth')
export class AuthController {
    constructor(private authService: AuthService) {}

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
        return this.authService.forgetPassword(data.email);
    }

    @Post('reset-password')
    @ApiOperation({ summary: 'Set new password using reset token' })
    @ApiBody({ type: ResetPasswordDto })
    @ApiOkWrapped('Password updated', { message: 'Password updated successfully' })
    resetPassword(@Body() data: ResetPasswordDto) {
        return this.authService.resetPassword(data.resetPasswordToken, data.newPassword);
    }

    @Post('verify-register-otp')
    @ApiOperation({ summary: 'Verify registration OTP' })
    @ApiBody({ type: VerifyOtpDto })
    @ApiOkWrapped('Account verified', { message: 'Account verified successfully' })
    verifyRegisterOtp(@Body() data: VerifyOtpDto) {
        return this.authService.verifyRegisterOtp(data.email, data.otp);
    }

    @Get('google/login')
    @UseGuards(AuthGuard('google'))
    @ApiOperation({
        summary: 'Start Google OAuth',
        description: 'Browser redirect to Google; not used as JSON API from mobile.',
    })
    googleLogin() {}

    @Get('google/callback')
    @UseGuards(AuthGuard('google'))
    @ApiOperation({ summary: 'Google OAuth callback (redirect)' })
    @ApiResponse({ status: 302, description: 'Redirect to frontend with token query param' })
    async googleCallback(
        @Req()
        req: {
            user: { id: number };
            ip?: string;
            headers: { 'user-agent'?: string; 'x-forwarded-for'?: string };
        },
        @Res() res: { redirect: (url: string) => void },
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
        const token = await this.authService.generateJWT(req.user, sessionContext);
        const base = process.env.FRONTEND_URL ?? 'http://localhost:3001';
        return res.redirect(`${base}/oauth-success?token=${token}`);
    }
}
