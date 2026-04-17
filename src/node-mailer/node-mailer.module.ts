import { Global, Module } from '@nestjs/common';
import { MailerModule } from '@nestjs-modules/mailer';
import { NodeMailerService } from './node-mailer.service';
require('dotenv').config();
@Global()
@Module({
    imports: [
        MailerModule.forRoot({
            transport: {
                host: process.env.MAIL_HOST, 
                port: 587,
                secure: false,
                auth: {
                    user: process.env.SMTP_USERNAME,
                    pass: process.env.SMTP_PASSWORD,
                },
            },
            defaults: {
                from: '"No Reply" <noreply@example.com>',
            },
        }),
    ],
    providers: [NodeMailerService],
    exports: [NodeMailerService],
})
export class NodeMailerModule { }
