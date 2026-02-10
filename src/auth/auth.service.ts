import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwtService: JwtService,
    ) { }
    generateOTP(): string {
        return Math.floor(100000 + Math.random() * 900000).toString();
    }

    async register(data: { email: string; password: string; name: string }) {
        const existingUser = await this.prisma.user.findUnique({
            where: { email: data.email }
        })
        if (existingUser) {
            throw new BadRequestException('Email already in use')
        }
        const hashedPassword = await bcrypt.hash(data.password, 10)

        const otp = this.generateOTP();
        const hashedOtp = crypto
            .createHash('sha256')
            .update(otp)
            .digest('hex');

        const user = await this.prisma.user.create({
            data: {
                email: data.email,
                passwordHash: hashedPassword,
                username: data.name,
                otpCode: hashedOtp,
                otpExpires: new Date(Date.now() + 15 * 60 * 1000)
            }
        })
        //mail server to otp
        const token = this.jwtService.sign({ userId: user.id })
        console.log('OTP:', otp);

        return { message: "Account Created Successfully" }
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
        return { message: "Account verified successfully" }
    }
    async login(data: { email: string; password: string }) {
        const user = await this.prisma.user.findUnique({
            where: { email: data.email },
        })
        if (!user) {
            throw new UnauthorizedException("Invalid credentials")
        }
        const passwordValid = await bcrypt.compare(data.password, user.passwordHash)
        if (!passwordValid) {
            throw new UnauthorizedException("Invalid credentials")
        }
        const token = this.jwtService.sign({ userId: user.id })
        return { user, token }
    }
    async forgetPassword(email: string) {
        const user = await this.prisma.user.findUnique({
            where: { email },
        });
        if (!user) {
            return { message: 'If email exists, reset link will be sent' };
        }
        const token = crypto.randomBytes(32).toString('hex');
        const hashedToken = crypto
            .createHash('sha256')
            .update(token)
            .digest('hex');

        await this.prisma.user.update({
            where: { id: user.id },
            data: {
                resetPasswordToken: hashedToken,
                resetPasswordExpires: new Date(Date.now() + 15 * 60 * 1000),
            },
        });
        const resetLink = `https://localhost:3000/reset-password?token=${token}`;
        //mail server
        return { message: 'Reset link sent if email exists', token };

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
}
