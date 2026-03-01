import { Injectable } from '@nestjs/common';
import { gmail_v1 } from 'googleapis';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const MailComposer = require('nodemailer/lib/mail-composer');

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
export class GmailSendProvider {
  async send(
    gmail: gmail_v1.Gmail,
    options: SendEmailOptions,
  ): Promise<string> {
    const mail = new MailComposer({
      from: options.from,
      to: options.to,
      cc: options.cc?.join(', '),
      bcc: options.bcc?.join(', '),
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
    });

    const raw = await mail.compile().build();
    const encoded = Buffer.from(raw)
      .toString('base64')
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=+$/, '');

    const res = await gmail.users.messages.send({
      userId: 'me',
      requestBody: { raw: encoded },
    });

    return res.data.id ?? '';
  }
}
