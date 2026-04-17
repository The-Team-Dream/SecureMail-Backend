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

    async resetPassword(user: User, token: string) {
        const resetLink = `https://localhost:3000/reset-password?token=${token}`;
        await this.mailerService.sendMail({
            to: user.email,
            from: '"Secure Mail" <support@securemail.com>',
            subject: 'Welcome to SecureMail App! Reset your Password',
            html: resetPasswordTemplate(user.username ?? 'User', resetLink)
        });
    }
}
