import { Injectable } from '@nestjs/common';
import * as nodemailer from 'nodemailer';
import { Transporter } from 'nodemailer';

export interface SmtpConfig {
  host: string;
  port: number;
  secure: boolean;
  auth: {
    user: string;
    pass: string;
  };
}

export interface SendEmailOptions {
  from: string;
  to: string;
  cc?: string[];
  bcc?: string[];
  subject: string;
  bodyText?: string;
  bodyHtml?: string;
  inReplyTo?: string;
  references?: string;
  attachments?: Array<{ filename: string; content: Buffer; contentType: string }>;
}

@Injectable()
export class SmtpSendProvider {
  async send(config: SmtpConfig, options: SendEmailOptions): Promise<void> {
    const transporter: Transporter = nodemailer.createTransport({
      host: config.host,
      port: config.port,
      secure: config.secure,
      auth: config.auth,
    });

    const mailOptions: nodemailer.SendMailOptions = {
      from: options.from,
      to: options.to,
      cc: options.cc,
      bcc: options.bcc,
      subject: options.subject,
      text: options.bodyText,
      html: options.bodyHtml,
      inReplyTo: options.inReplyTo,
      references: options.references,
      attachments: options.attachments?.map((a) => ({
        filename: a.filename,
        content: a.content,
        contentType: a.contentType,
      })),
    };

    await transporter.sendMail(mailOptions);
  }
}
