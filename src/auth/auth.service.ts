import { BadRequestException, ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import { NodeMailerService } from 'src/node-mailer/node-mailer.service';
import { User, ThemeMode } from '@prisma/client';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import Redis from 'ioredis';
import { InjectRedis } from '@nestjs-modules/ioredis';
import { SessionsService } from 'src/sessions/sessions.service';
import { EncryptionService } from 'src/common/encryption/encryption.service';

const SESSION_EXPIRY_DAYS = 7;

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwtService: JwtService,
        private mailerService: NodeMailerService,
        private sessionsService: SessionsService,
        private encryptionService: EncryptionService,
        @InjectRedis() private readonly redis: Redis
    ) { }

    async generateJWT(
        user: Pick<User, 'id'>,
        sessionContext?: { ipAddress: string; userAgent: string },
    ): Promise<string> {
        if (!sessionContext) {
            return this.jwtService.signAsync({ userId: user.id });
        }
        const expiresAt = new Date(Date.now() + SESSION_EXPIRY_DAYS * 24 * 60 * 60 * 1000);
        const sessionId = await this.sessionsService.createSession({
            userId: user.id,
            ipAddress: sessionContext.ipAddress,
            userAgent: sessionContext.userAgent,
            expiresAt,
        });
        return this.jwtService.signAsync(
            { userId: user.id, sessionId },
            { expiresIn: `${SESSION_EXPIRY_DAYS}d` },
        );
    }

    async blacklistToken(token: string, expiresIn: number) {
        const decoded = this.jwtService.decode(token) as { sessionId?: number; userId?: number; exp?: number };
        if (decoded?.sessionId && decoded?.userId) {
            try {
                await this.sessionsService.revokeSession(decoded.sessionId, decoded.userId);
            } catch {
                await this.sessionsService.blacklistSession(decoded.sessionId, new Date((decoded.exp ?? 0) * 1000));
            }
        } else {
            await this.redis.set(`bl:${token}`, 'blacklisted', 'EX', expiresIn);
        }
    }

    async isBlacklisted(token: string): Promise<boolean> {
        const decoded = this.jwtService.decode(token) as { sessionId?: number };
        if (decoded?.sessionId) {
            return this.sessionsService.isSessionBlacklisted(decoded.sessionId);
        }
        const result = await this.redis.get(`bl:${token}`);
        return !!result;
    }
    async generateOTP(): Promise<string> {
        return crypto.randomInt(100000, 999999).toString();
    }
    async register(data: RegisterDto) {
        const existingUser = await this.prisma.user.findUnique({ where: { email: data.email } })
        if (existingUser) {
            if (!existingUser.isVerified) {
                // Unverified account exists — tell user to resend OTP instead
                throw new BadRequestException('Account already registered but not verified. Use resend-otp to get a new code.')
            }
            throw new BadRequestException('Email already in use')
        }
        const hashedPassword = await bcrypt.hash(data.password, 10)

        const otp = await this.generateOTP();
        const hashedOtp = crypto
            .createHash('sha256')
            .update(otp)
            .digest('hex');

        const user = await this.prisma.user.create({
            data: {
                email: data.email,
                passwordHash: hashedPassword,
                username: data.username,
                otpCode: hashedOtp,
                otpExpires: new Date(Date.now() + 15 * 60 * 1000),
                settings: {
                    create: {
                        notificationsEnabled: true,
                        themeMode: ThemeMode.LIGHT,
                    },
                },
            }
        })
        await this.mailerService.sendOTP(user, otp)
        return { message: "OTP sent to your email" }
    }

    async resendOtp(email: string) {
        // Cooldown check — prevent abuse (60 seconds between resends)
        const cooldownKey = `otp_cooldown:${email}`;
        const onCooldown = await this.redis.get(cooldownKey);
        if (onCooldown) {
            // Generic message: don't reveal whether email exists
            return { message: 'If your account is pending verification, a new OTP has been sent.' };
        }

        const user = await this.prisma.user.findFirst({
            where: { email, isVerified: false },
        });

        if (!user) {
            // Set cooldown regardless to prevent timing-based enumeration
            await this.redis.set(cooldownKey, '1', 'EX', 60);
            return { message: 'If your account is pending verification, a new OTP has been sent.' };
        }

        const otp = await this.generateOTP();
        const hashedOtp = crypto.createHash('sha256').update(otp).digest('hex');

        await this.prisma.user.update({
            where: { id: user.id },
            data: {
                otpCode: hashedOtp,
                otpExpires: new Date(Date.now() + 15 * 60 * 1000),
            },
        });

        await this.mailerService.sendOTP(user, otp);

        // Set 60-second cooldown
        await this.redis.set(cooldownKey, '1', 'EX', 60);

        return { message: 'If your account is pending verification, a new OTP has been sent.' };
    }

    async login(
        data: LoginDto,
        sessionContext?: { ipAddress: string; userAgent: string },
    ) {
        const user = await this.prisma.user.findUnique({ where: { email: data.email } })
        if (!user) {
            throw new UnauthorizedException("Invalid credentials")
        }
        if (user.deletedAt) {
            throw new UnauthorizedException("Invalid credentials")
        }
        if (user.bannedAt) {
            throw new ForbiddenException("Account has been banned")
        }
        if (!user.passwordHash || user.provider !== "local") {
            throw new UnauthorizedException("Invalid credentials");
        }
        const passwordValid = await bcrypt.compare(data.password, user.passwordHash)
        if (!passwordValid) {
            throw new UnauthorizedException("Invalid credentials")
        }
        if (user.totpEnabled) {
            const tempToken = await this.jwtService.signAsync(
                { userId: user.id, pending2FA: true },
                { expiresIn: '5m' },
            );
            return { requires2FA: true, tempToken };
        }
        const token = await this.generateJWT(user, sessionContext);
        return { token };
    }

    async verify2FA(
        tempToken: string,
        code: string,
        sessionContext?: { ipAddress: string; userAgent: string },
    ) {
        const payload = await this.jwtService.verifyAsync(tempToken);
        if (!payload.pending2FA || !payload.userId) {
            throw new UnauthorizedException("Invalid or expired token");
        }
        const user = await this.prisma.user.findUnique({
            where: { id: payload.userId },
            select: { id: true, totpSecret: true, totpEnabled: true, bannedAt: true, deletedAt: true },
        });
        if (!user) throw new UnauthorizedException("Invalid or expired token");
        if (user.deletedAt) throw new UnauthorizedException("Account has been deleted");
        if (user.bannedAt) throw new ForbiddenException("Account has been banned");
        if (!user.totpEnabled || !user.totpSecret) {
            throw new UnauthorizedException("2FA not enabled for this account");
        }
        const { verifySync } = await import('otplib');
        const result = verifySync({ secret: user.totpSecret, token: code });
        if (!result.valid) {
            throw new UnauthorizedException("Invalid TOTP code");
        }
        const token = await this.generateJWT({ id: user.id } as User, sessionContext);
        return { token };
    }

    async logout(token: string) {
        const decoded = this.jwtService.decode(token) as { exp?: number };
        const exp = decoded?.exp ?? 0;
        const now = Math.floor(Date.now() / 1000);
        const ttl = Math.max(0, exp - now);
        await this.blacklistToken(token, ttl);
        return { message: "Logout successfully" }
    }
    async verifyRegisterOtp(email: string, otp: string) {
        const hashedOtp = crypto
            .createHash('sha256')
            .update(otp)
            .digest('hex');

        const user = await this.prisma.user.findFirst({
            where: {
                email: email,
                isVerified: false,
                otpCode: hashedOtp,
                otpExpires: { gt: new Date() }
            }
        })
        if (!user) {
            throw new BadRequestException("OTP invalid or expired")
        }
        await this.prisma.user.update({
            where: { id: user.id },
            data: {
                isVerified: true,
                otpCode: null,
                otpExpires: null
            }
        })
        await this.mailerService.welcome(user)
        return { message: "Account verified successfully" }
    }

    async forgetPassword(email: string) {
        const user = await this.prisma.user.findUnique({
            where: { email },
        });
        if (!user) {
            return { message: 'If email exists, reset link will be sent' };
        }
        const resetToken = crypto.randomBytes(32).toString('hex');
        const hashedToken = crypto
            .createHash('sha256')
            .update(resetToken)
            .digest('hex');

        await this.prisma.user.update({
            where: { id: user.id },
            data: {
                resetPasswordToken: hashedToken,
                resetPasswordExpires: new Date(Date.now() + 15 * 60 * 1000),
            },
        });
        await this.mailerService.resetPassword(user, resetToken)
        return { message: 'If email exists, reset link will be sent' };
    }

    async resetPassword(token: string, newPassword: string) {
        const hashedToken = crypto
            .createHash('sha256')
            .update(token)
            .digest('hex');

        const user = await this.prisma.user.findFirst({
            where: {
                resetPasswordToken: hashedToken,
                resetPasswordExpires: {
                    gt: new Date(),
                },
            },
        });

        if (!user) {
            throw new BadRequestException('Invalid or expired token');
        }
        const hashedPassword = await bcrypt.hash(newPassword, 10);
        await this.prisma.user.update({
            where: { id: user.id },
            data: {
                passwordHash: hashedPassword,
                resetPasswordToken: null,
                resetPasswordExpires: null,
            },
        });
        return { message: 'Password updated successfully' };
    }
    async validateGoogleUser(data: {
        googleId: string;
        provider: string;
        email: string;
        firstName?: string;
        lastName?: string;
        avatar?: string;
        accessToken: string;
        refreshToken: string
    }) {
        let user = await this.prisma.user.findUnique({
            where: { email: data.email },
        });

        if (user) {
            if (user.provider !== "google" || !user.oauthId) {
                throw new UnauthorizedException("Unauthorized")
            }
            user = await this.prisma.user.update({
                where: { email: data.email },
                data: {
                    oauthId: data.googleId,
                    oauthAccessToken: this.encryptionService.encrypt(data.accessToken),
                    oauthRefreshToken: data.refreshToken
                        ? this.encryptionService.encrypt(data.refreshToken)
                        : null,
                },
            });
        } else {
            user = await this.prisma.user.create({
                data: {
                    email: data.email,
                    username: `${data.firstName}${data.lastName ?? ''}`,
                    avatar: data.avatar,
                    provider: 'google',
                    oauthId: data.googleId,
                    isVerified: true,
                    oauthAccessToken: this.encryptionService.encrypt(data.accessToken),
                    oauthRefreshToken: data.refreshToken
                        ? this.encryptionService.encrypt(data.refreshToken)
                        : null,
                    settings: {
                        create: {
                            notificationsEnabled: true,
                            themeMode: ThemeMode.LIGHT,
                        },
                    },
                },
            });
        }

        return user
    }

}
//logout
