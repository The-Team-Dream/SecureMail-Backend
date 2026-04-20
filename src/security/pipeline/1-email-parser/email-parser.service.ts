
import { Injectable, Logger } from '@nestjs/common';
import { ParsedAttachment, ParsedEmail, RawAuthHeaders, RawEmailInput } from 'src/security/types';

@Injectable()
export class EmailParserService {
  private readonly logger = new Logger(EmailParserService.name);

  parse(raw: RawEmailInput): ParsedEmail {
    try {
      return this.doParse(raw);
    } catch (err) {
      this.logger.error('EmailParserService.parse failed', {
        emailId: raw.emailId,
        error: err instanceof Error ? err.message : String(err),
      });
      return this.buildFallback(raw);
    }
  }

  private doParse(raw: RawEmailInput): ParsedEmail {
    const fromAddr = raw.fromAddr ?? '';
    const fromFullDomain = this.extractDomain(fromAddr);
    const fromDomain = fromFullDomain ? this.extractBaseDomain(fromFullDomain) : null;
    const bodyText = raw.bodyText ?? null;
    const bodyHtml = raw.bodyHtml ?? null;
    const bodyPlain = bodyText ?? this.stripHtml(bodyHtml ?? '');
    const urls = this.extractUrls(bodyHtml, bodyText);
    const urlDomains = this.extractUrlDomains(urls);
    const headers = raw.headers ?? null;
    const authHeaders = this.extractAuthHeaders(headers);
    const subject = raw.subject ?? '';
    const inReplyTo = raw.inReplyTo ?? this.getHeader(headers, 'in-reply-to');
    const refsHeader = raw.references ?? this.getHeader(headers, 'references');
    const isReplyThread = this.detectReplyThread(subject, inReplyTo);
    const attachments: ParsedAttachment[] = (raw.attachments ?? []).map(a => ({
      filename: a.filename,
      mimeType: a.mimeType,
      size: a.size,
      storagePath: a.storagePath,
    }));
    return {
      emailId: String(raw.emailId),
      messageId: raw.messageId,
      mailBoxId: raw.mailBoxId,
      fromAddr,
      fromName: raw.fromName ?? null,
      fromDomain,
      fromFullDomain,
      senderIp: this.extractSenderIp(headers),
      toAddr: this.normalizeAddrList(raw.toAddr),
      ccAddr: this.normalizeAddrList(raw.ccAddr),
      bccAddr: this.normalizeAddrList(raw.bccAddr),
      replyTo: raw.replyTo ?? this.getHeader(headers, 'reply-to'),
      inReplyTo,
      references: refsHeader,
      isReplyThread,
      subject,
      bodyText,
      bodyHtml,
      bodyPlain,
      urls,
      urlDomains,
      attachments,
      hasAttachment: attachments.length > 0,
      headers,
      authHeaders,
      receivedAt: raw.receivedAt ?? new Date(),
    };
  }

  extractUrls(html: string | null, text: string | null): string[] {
    const found = new Set<string>();
    if (html) {
      const hrefRe = /(?:href|src)\s*=\s*['"]?(https?:\/\/[^'">\s]+)/gi;
      let m: RegExpExecArray | null;
      while ((m = hrefRe.exec(html)) !== null) {
        found.add(m[1].trim());
      }
    }

    if (text) {
      const urlRe = /https?:\/\/[^\s'"<>()[\]{}]+/gi;
      let m2: RegExpExecArray | null;
      while ((m2 = urlRe.exec(text)) !== null) {
        found.add(m2[0].trim());
      }
    }
    return [...found].filter(Boolean);
  }

  private extractUrlDomains(urls: string[]): string[] {
    const domains = new Set<string>();
    for (const url of urls) {
      const d = this.extractDomainFromUrl(url);
      if (d) domains.add(d);
    }
    return [...domains];
  }

  private extractAuthHeaders(headers: Record<string, string | string[]> | null): RawAuthHeaders {
    if (!headers) return {};
    return {
      authenticationResults: headers['authentication-results'] ?? headers['Authentication-Results'],
      spf: headers['received-spf'] ?? headers['Received-SPF'],
      dkim: headers['dkim-signature'] ?? headers['DKIM-Signature'],
      dmarc: headers['dmarc-filter'] ?? headers['DMARC-Filter'],
      arc: headers['arc-authentication-results'] ?? headers['ARC-Authentication-Results'],
    };
  }

  private detectReplyThread(subject: string, inReplyTo: string | null): boolean {
    if (inReplyTo) return true;
    const s = subject.toLowerCase().trim();
    return (
      s.startsWith('re:') || s.startsWith('fwd:') || s.startsWith('fw:') ||
      s.startsWith('رد:') || s.startsWith('ر:') || s.startsWith('aw:') ||
      s.startsWith('rép:') || s.startsWith('sv:')
    );
  }

  private getHeader(
    headers: Record<string, string | string[]> | null,
    name: string,
  ): string | null {
    if (!headers) return null;
    const val = headers[name] ?? headers[name.toLowerCase()] ?? headers[name.toUpperCase()];
    if (!val) return null;
    return Array.isArray(val) ? val[0] : val;
  }

  private normalizeAddrList(raw: string | string[] | null | undefined): string[] {
    if (!raw) return [];
    if (Array.isArray(raw)) return raw.filter(Boolean);
    return [raw].filter(Boolean);
  }

  extractDomain(addr: string): string | null {
    if (!addr) return null;
    const angleMatch = addr.match(/<([^>]+)>/);
    const email = angleMatch ? angleMatch[1] : addr.trim();
    const atIdx = email.lastIndexOf('@');
    return atIdx >= 0 ? email.slice(atIdx + 1).toLowerCase().trim() : null;
  }

  extractBaseDomain(domain: string): string | null {
    if (!domain) return null;
    const parts = domain.split('.');
    if (parts.length < 2) return domain;
    const ccTLD = ['co', 'com', 'net', 'org', 'gov', 'edu', 'ac'];
    if (parts.length >= 3 && ccTLD.includes(parts[parts.length - 2])) {
      return parts[parts.length - 3];
    }
    return parts[parts.length - 2];
  }

  private extractDomainFromUrl(url: string): string | null {
    try {
      return new URL(url).hostname.replace(/^www\./, '').toLowerCase();
    } catch {
      return null;
    }
  }

  private extractSenderIp(headers: Record<string, string | string[]> | null,): string | null {
    if (!headers) return '';
    const received = headers['received'] ?? headers['Received'];
    const receivedStr = Array.isArray(received) ? received[0] : (received ?? '');
    const ipMatch = receivedStr.match(/\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]/);
    return ipMatch ? ipMatch[1] : '';
  }

  stripHtml(html: string): string {
    return html
      .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, ' ')
      .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, ' ')
      .replace(/<[^>]+>/g, ' ')
      .replace(/&nbsp;/g, ' ')
      .replace(/&amp;/g, '&')
      .replace(/&lt;/g, '<')
      .replace(/&gt;/g, '>')
      .replace(/\s{2,}/g, ' ')
      .trim()
  }

  private buildFallback(raw: RawEmailInput): ParsedEmail {
    return {
      emailId: String(raw.emailId),
      messageId: raw.messageId ?? '',
      mailBoxId: raw.mailBoxId,
      fromAddr: raw.fromAddr ?? '',
      fromName: null,
      fromDomain: null,
      fromFullDomain: null,
      senderIp: null,
      toAddr: [], ccAddr: [], bccAddr: [],
      replyTo: null, inReplyTo: null, references: null, isReplyThread: false,
      subject: raw.subject ?? '',
      bodyText: null, bodyHtml: null, bodyPlain: '',
      urls: [], urlDomains: [], attachments: [], hasAttachment: false,
      headers: null, authHeaders: {},
      receivedAt: new Date(),
    };
  }
}
