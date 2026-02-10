import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import * as crypto from 'crypto';
import { NodeMailerService } from 'src/node-mailer/node-mailer.service';

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwtService: JwtService,
        private mailerService: NodeMailerService
    ) { }
    generateOTP(): string {
        return Math.floor(100000 + Math.random() * 900000).toString();
    }

    async register(data: { email: string; password: string; username: string }) {
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
                username: data.username,
                otpCode: hashedOtp,
                otpExpires: new Date(Date.now() + 15 * 60 * 1000)
            }
        })
        const token = this.jwtService.sign({ userId: user.id })
        await this.mailerService.sendOTP(user,otp)
        return {otp}
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
    async login(data: { email: string; password: string }) {
        const user = await this.prisma.user.findUnique({
            where: { email: data.email },
            select:{
                id:true,
                passwordHash:true,
            }
        })
        if (!user) {
            throw new UnauthorizedException("Invalid credentials")
        } 
        const passwordValid = await bcrypt.compare(data.password, user.passwordHash)
        if (!passwordValid) {
            throw new UnauthorizedException("Invalid credentials") 
        }
        const token = this.jwtService.sign({ userId: user.id })
        return { token }
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
        return { resetToken };
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
