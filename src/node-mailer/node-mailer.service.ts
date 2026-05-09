import { MailerService } from '@nestjs-modules/mailer';
import { Injectable } from '@nestjs/common';
import { User } from '@prisma/client';
import { welcomeTemplate } from './templates/welcome';
import { otpTemplate } from './templates/otp';
import { resetPasswordTemplate } from './templates/resetpassword';

@Injectable()
export class NodeMailerService {
    constructor(private mailerService: MailerService) { }

    async welcome(user: User) {

        await this.mailerService.sendMail({
            to: user.email,
            from: '"Secure Mail" <support@securemail.com>',
            subject: 'Welcome to SecureMail App!',
            html: welcomeTemplate(user.username ?? 'User')
        });
    }

    async sendOTP(user: User, otp: string) {
        await this.mailerService.sendMail({
            to: user.email,
            from: '"Secure Mail" <support@securemail.com>',
            subject: 'Welcome to SecureMail App! Confirm your Email',
            html: otpTemplate(user.username ?? 'User', otp)
        });
    }

    async resetPassword(user: User, tokenOrLink: string, clientType: 'web' | 'mobile' = 'web') {
        let contentLink: string;

        if (clientType === 'mobile') {
            // للموبايل نستخدم رابط بريدج (HTTPS) لكي يقبل تطبيق الإيميل الضغط عليه
            const deepLink = `securemail://app/reset-password?token=${tokenOrLink}`;
            const backendUrl = process.env.BACKEND_URL ?? 'http://10.0.0.106:3000';
            contentLink = `${backendUrl}/auth/redirect?url=${encodeURIComponent(deepLink)}`;
        } else {
            // للويب نستخدم الرابط الكامل
            contentLink = tokenOrLink.startsWith('http')
                ? tokenOrLink
                : `${process.env.FRONTEND_URL}/reset-password?token=${tokenOrLink}`;
        }

        await this.mailerService.sendMail({
            to: user.email,
            from: '"Secure Mail" <support@securemail.com>',
            subject: 'Welcome to SecureMail App! Reset your Password',
            html: resetPasswordTemplate(user.username ?? 'User', contentLink)
        });
    }
}
