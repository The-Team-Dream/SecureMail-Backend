import { Injectable } from '@nestjs/common';
import { Client } from '@microsoft/microsoft-graph-client';
import 'isomorphic-fetch';

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
export class OutlookSendProvider {
  async send(client: Client, options: SendEmailOptions): Promise<void> {
    const message: Record<string, unknown> = {
      subject: options.subject,
      body: {
        contentType: options.bodyHtml ? 'HTML' : 'Text',
        content: options.bodyHtml ?? options.bodyText ?? '',
      },
      toRecipients: options.to.split(',').map((addr) => ({
        emailAddress: { address: addr.trim() },
      })),
    };

    if (options.cc?.length) {
      message.ccRecipients = options.cc.map((addr) => ({
        emailAddress: { address: addr.trim() },
      }));
    }
    if (options.bcc?.length) {
      message.bccRecipients = options.bcc.map((addr) => ({
        emailAddress: { address: addr.trim() },
      }));
    }
    if (options.inReplyTo) {
      (message as { internetMessageHeaders?: Array<{ name: string; value: string }> }).internetMessageHeaders = [
        { name: 'In-Reply-To', value: options.inReplyTo },
        ...(options.references ? [{ name: 'References', value: options.references }] : []),
      ];
    }

    if (options.attachments?.length) {
      message.attachments = options.attachments.map((a) => ({
        '@odata.type': '#microsoft.graph.fileAttachment',
        name: a.filename,
        contentType: a.contentType,
        contentBytes: a.content.toString('base64'),
      }));
    }

    await client.api('/me/sendMail').post({ message });
  }
}
