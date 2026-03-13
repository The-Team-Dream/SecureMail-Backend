// ─────────────────────────────────────────────────────────────────────────────
// email-parser/email-parser.service.ts
//
// Email Parsing Engine — Stage 1 of the Security Pipeline.
//
// Responsibility: Accept raw email data (as stored in DB / received from IMAP)
// and produce a normalized ParsedEmail object consumed by every downstream
// stage. No detection logic lives here — pure normalization.
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable, Logger } from '@nestjs/common';

// ─── Parsed Attachment ────────────────────────────────────────────────────────
export interface ParsedAttachment {
  filename:    string;
  mimeType:    string;
  size:        number;
  storagePath: string;
  sha256?:     string; // populated by malware stage after hash computation
}

// ─── Authentication Header Tokens (raw strings before structured parsing) ────
export interface RawAuthHeaders {
  spf?:   string | string[];
  dkim?:  string | string[];
  dmarc?: string | string[];
  arc?:   string | string[];
  authenticationResults?: string | string[];
}

// ─── ParsedEmail — canonical object flowing through the entire pipeline ────────
export interface ParsedEmail {
  // ── Identifiers ────────────────────────────────────────────────────────────
  emailId:   string;   // DB id as string
  messageId: string;   // RFC 2822 Message-ID
  mailBoxId: number;

  // ── Sender ─────────────────────────────────────────────────────────────────
  fromAddr:     string;
  fromName:     string | null;
  fromDomain:   string | null;  // extracted base domain  e.g. "paypal"
  fromFullDomain: string | null; // full domain            e.g. "mail.paypal.com"

  // ── Recipients ─────────────────────────────────────────────────────────────
  toAddr:  string[];
  ccAddr:  string[];
  bccAddr: string[];

  // ── Threading ──────────────────────────────────────────────────────────────
  replyTo:   string | null;
  inReplyTo: string | null;
  references: string | null;
  isReplyThread: boolean;

  // ── Content ────────────────────────────────────────────────────────────────
  subject:   string;
  bodyText:  string | null;
  bodyHtml:  string | null;
  bodyPlain: string;   // bodyText ?? stripHtml(bodyHtml) — pre-computed

  // ── Extracted signals ──────────────────────────────────────────────────────
  urls:         string[];   // all hrefs extracted from HTML + text
  urlDomains:   string[];   // unique domains from urls
  attachments:  ParsedAttachment[];
  hasAttachment: boolean;

  // ── Raw Headers ────────────────────────────────────────────────────────────
  headers:     Record<string, string | string[]> | null;
  authHeaders: RawAuthHeaders;

  // ── Timing ─────────────────────────────────────────────────────────────────
  receivedAt: Date;
}

// ─── Input type matching what exists in the sync processor ───────────────────
export interface RawEmailInput {
  emailId:    number | string;
  messageId:  string;
  mailBoxId:  number;
  fromAddr:   string;
  fromName?:  string | null;
  toAddr?:    string | string[];
  ccAddr?:    string | string[] | null;
  bccAddr?:   string | string[] | null;
  replyTo?:   string | null;
  inReplyTo?: string | null;
  references?: string | null;
  subject:    string;
  bodyText?:  string | null;
  bodyHtml?:  string | null;
  headers?:   Record<string, string | string[]> | null;
  attachments?: Array<{
    filename:    string;
    mimeType:    string;
    size:        number;
    storagePath: string;
  }>;
  receivedAt?: Date;
}

@Injectable()
export class EmailParserService {
  private readonly logger = new Logger(EmailParserService.name);

  /**
   * parse() — primary entry point.
   *
   * Takes raw email data as stored / received and normalizes it into a
   * fully-structured ParsedEmail consumed by every security stage.
   */
  parse(raw: RawEmailInput): ParsedEmail {
    try {
      return this.doParse(raw);
    } catch (err) {
      this.logger.error('EmailParserService.parse failed', {
        emailId: raw.emailId,
        error:   err instanceof Error ? err.message : String(err),
      });
      // Return a minimal safe object so the pipeline can continue
      return this.buildFallback(raw);
    }
  }

  // ─── Core parsing logic ────────────────────────────────────────────────────
  private doParse(raw: RawEmailInput): ParsedEmail {
    const fromAddr      = raw.fromAddr ?? '';
    const fromFullDomain = this.extractDomain(fromAddr);
    const fromDomain     = fromFullDomain ? this.extractBaseDomain(fromFullDomain) : null;

    const bodyText = raw.bodyText ?? null;
    const bodyHtml = raw.bodyHtml ?? null;
    const bodyPlain = bodyText ?? this.stripHtml(bodyHtml ?? '');

    const urls       = this.extractUrls(bodyHtml, bodyText);
    const urlDomains = this.extractUrlDomains(urls);

    const headers     = raw.headers ?? null;
    const authHeaders = this.extractAuthHeaders(headers);

    const subject      = raw.subject ?? '';
    const inReplyTo    = raw.inReplyTo ?? this.getHeader(headers, 'in-reply-to');
    const refsHeader   = raw.references ?? this.getHeader(headers, 'references');
    const isReplyThread = this.detectReplyThread(subject, inReplyTo);

    const attachments: ParsedAttachment[] = (raw.attachments ?? []).map(a => ({
      filename:    a.filename,
      mimeType:    a.mimeType,
      size:        a.size,
      storagePath: a.storagePath,
    }));

    return {
      emailId:        String(raw.emailId),
      messageId:      raw.messageId,
      mailBoxId:      raw.mailBoxId,

      fromAddr,
      fromName:       raw.fromName ?? null,
      fromDomain,
      fromFullDomain,

      toAddr:  this.normalizeAddrList(raw.toAddr),
      ccAddr:  this.normalizeAddrList(raw.ccAddr),
      bccAddr: this.normalizeAddrList(raw.bccAddr),

      replyTo:   raw.replyTo ?? this.getHeader(headers, 'reply-to'),
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

  // ─── URL extraction ────────────────────────────────────────────────────────
  // FIX-7: فصلنا HTML extraction عن plain text extraction
  // المشكلة: الكود القديم كان بيعمل stripHtml(html) وبعدين يبحث فيه بالـ URL regex
  // — ده كان بيضيف URLs من HTML مرتين (مرة من href، ومرة من stripped text)
  // الحل: HTML → href/src فقط | plain text → URL regex فقط
  extractUrls(html: string | null, text: string | null): string[] {
    const found = new Set<string>();

    // ── Source 1: HTML href / src attributes only ─────────────────────────────
    // FIX-7: لا نعمل stripHtml هنا — هنبحث في الـ attributes مباشرة
    if (html) {
      const hrefRe = /(?:href|src)\s*=\s*['"]?(https?:\/\/[^'">\s]+)/gi;
      let m: RegExpExecArray | null;
      while ((m = hrefRe.exec(html)) !== null) {
        found.add(m[1].trim());
      }
    }

    // ── Source 2: Bare URLs in plain text only ────────────────────────────────
    // FIX-7: نبحث في text فقط، مش في stripped HTML
    // لو html موجود بس text مش موجود → مش بنعمل stripHtml هنا
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

  // ─── Auth header extraction ────────────────────────────────────────────────
  private extractAuthHeaders(headers: Record<string, string | string[]> | null): RawAuthHeaders {
    if (!headers) return {};
    return {
      authenticationResults: headers['authentication-results'] ?? headers['Authentication-Results'],
      spf:  headers['received-spf']  ?? headers['Received-SPF'],
      dkim: headers['dkim-signature'] ?? headers['DKIM-Signature'],
      dmarc: headers['dmarc-filter']  ?? headers['DMARC-Filter'],
      arc:  headers['arc-authentication-results'] ?? headers['ARC-Authentication-Results'],
    };
  }

  // ─── Reply-thread detection ────────────────────────────────────────────────
  private detectReplyThread(subject: string, inReplyTo: string | null): boolean {
    if (inReplyTo) return true;
    const s = subject.toLowerCase().trim();
    return (
      s.startsWith('re:')  || s.startsWith('fwd:') || s.startsWith('fw:') ||
      s.startsWith('رد:')  || s.startsWith('ر:')   || s.startsWith('aw:') ||
      s.startsWith('rép:') || s.startsWith('sv:')
    );
  }

  // ─── Header utilities ──────────────────────────────────────────────────────
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

  // ─── Domain utilities (self-contained, no import needed) ──────────────────
  extractDomain(addr: string): string | null {
    if (!addr) return null;
    const angleMatch = addr.match(/<([^>]+)>/);
    const email      = angleMatch ? angleMatch[1] : addr.trim();
    const atIdx      = email.lastIndexOf('@');
    return atIdx >= 0 ? email.slice(atIdx + 1).toLowerCase().trim() : null;
  }

  extractBaseDomain(domain: string): string | null {
    if (!domain) return null;
    const parts = domain.split('.');
    if (parts.length < 2) return domain;
    // Handle ccTLDs like .co.uk, .com.au, .com.eg
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

  // ─── HTML stripping ────────────────────────────────────────────────────────
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
      .toLowerCase();
  }

  // ─── Fallback on error ─────────────────────────────────────────────────────
  private buildFallback(raw: RawEmailInput): ParsedEmail {
    return {
      emailId:   String(raw.emailId),
      messageId: raw.messageId ?? '',
      mailBoxId: raw.mailBoxId,
      fromAddr:  raw.fromAddr ?? '',
      fromName:  null,
      fromDomain: null,
      fromFullDomain: null,
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
