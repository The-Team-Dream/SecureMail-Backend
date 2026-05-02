import { Injectable } from '@nestjs/common';
import { ImapFlow } from 'imapflow';
import { simpleParser, ParsedMail } from 'mailparser';

export interface ImapConnectionConfig {
  host: string;
  port: number;
  secure: boolean;
  auth: {
    user: string;
    pass: string;
  };
}

export interface ImapMessageSummary {
  uid: number;
  envelope: {
    messageId?: string;
    subject?: string;
    from?: Array<{ address?: string; name?: string }>;
    to?: Array<{ address?: string; name?: string }>;
    cc?: Array<{ address?: string; name?: string }>;
    bcc?: Array<{ address?: string; name?: string }>;
    date?: Date;
  };
  flags: Set<string>;
}

export interface ImapParsedMessage {
  from: string;
  to: string[];
  cc: string[];
  bcc: string[];
  subject: string;
  text?: string;
  html?: string;
  date?: Date;
  messageId?: string;
  attachments: Array<{ filename: string; mimeType: string; size: number; content: Buffer }>;
}

@Injectable()
export class ImapProvider {
  async testConnection(config: ImapConnectionConfig): Promise<boolean> {
    const client = new ImapFlow({
      host: config.host,
      port: config.port,
      secure: config.secure,
      auth: config.auth,
    });
    try {
      await client.connect();
      return true;
    } finally {
      await client.logout();
    }
  }

  async connect(config: ImapConnectionConfig): Promise<ImapFlow> {
    const client = new ImapFlow({
      host: config.host,
      port: config.port,
      secure: config.secure,
      auth: config.auth,
    });
    await client.connect();
    return client;
  }

  async fetchMessages(
    client: ImapFlow,
    mailbox: string,
    limit = 50,
  ): Promise<ImapMessageSummary[]> {
    const lock = await client.getMailboxLock(mailbox);
    try {
      const messages: ImapMessageSummary[] = [];
      let count = 0;
      for await (const msg of client.fetch(
        { seen: false },
        { envelope: true, uid: true, flags: true },
      )) {
        messages.push({
          uid: msg.uid,
          envelope: msg.envelope as ImapMessageSummary['envelope'],
          flags: msg.flags ?? new Set(),
        });
        count++;
        if (count >= limit) break;
      }
      if (messages.length < limit) {
        for await (const msg of client.fetch(
          { seen: true },
          { envelope: true, uid: true, flags: true },
        )) {
          if (messages.some((m) => m.uid === msg.uid)) continue;
          messages.push({
            uid: msg.uid,
            envelope: msg.envelope as ImapMessageSummary['envelope'],
            flags: msg.flags ?? new Set(),
          });
          count++;
          if (count >= limit) break;
        }
      }
      return messages.sort(
        (a, b) =>
          (b.envelope.date?.getTime() ?? 0) - (a.envelope.date?.getTime() ?? 0),
      );
    } finally {
      lock.release();
    }
  }

  async fetchFullMessage(
    client: ImapFlow,
    _mailbox: string,
    uid: number,
  ): Promise<ImapParsedMessage> {
    const lock = await client.getMailboxLock(_mailbox);
    try {
      for await (const msg of client.fetch(
        { uid },
        { uid: true, source: true },
      )) {
        if (msg.source) {
          const parsed = await simpleParser(msg.source as Buffer);
          return this.parseMailToMessage(parsed);
        }
      }
      return {
        from: '',
        to: [],
        cc: [],
        bcc: [],
        subject: '',
        attachments: [],
      };
    } finally {
      lock.release();
    }
  }

  private parseMailToMessage(parsed: ParsedMail): ImapParsedMessage {
    const from = parsed.from?.value?.[0]
      ? `${parsed.from.value[0].name ? `"${parsed.from.value[0].name}" ` : ''}<${parsed.from.value[0].address}>`
      : parsed.from?.text ?? '';
    const to = parsed.to?.value?.map((a) => a.address ?? '') ?? [];
    const cc = parsed.cc?.value?.map((a) => a.address ?? '') ?? [];
    const bcc = parsed.bcc?.value?.map((a) => a.address ?? '') ?? [];
    const attachments =
      parsed.attachments?.map((a) => ({
        filename: a.filename ?? 'unknown',
        mimeType: a.contentType ?? 'application/octet-stream',
        size: a.size ?? 0,
        content: a.content,
      })) ?? [];
    return {
      from,
      to,
      cc,
      bcc,
      subject: parsed.subject ?? '',
      text: parsed.text,
      html: parsed.html ?? undefined,
      date: parsed.date,
      messageId: parsed.messageId,
      attachments,
    };
  }

  getFolderMapping(): Record<string, string> {
    return {
      INBOX: 'INBOX',
      SENT: 'Sent',
      SPAM: 'Junk',
    };
  }
}
