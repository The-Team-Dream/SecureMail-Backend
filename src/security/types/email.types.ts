export interface RawEmailInput {
    emailId: number | string;
    messageId: string;
    mailBoxId: number;
    fromAddr: string;
    fromName?: string | null;
    toAddr?: string | string[];
    ccAddr?: string | string[] | null;
    bccAddr?: string | string[] | null;
    replyTo?: string | null;
    inReplyTo?: string | null;
    references?: string | null;
    subject: string;
    bodyText?: string | null;
    bodyHtml?: string | null;
    headers?: Record<string, string | string[]> | null;
    attachments?: Array<{
        filename: string;
        mimeType: string;
        size: number;
        storagePath: string;
    }>;
    receivedAt?: Date;
}
export interface ParsedEmail {
    emailId: string;
    messageId: string;
    mailBoxId: number;
    fromAddr: string;
    fromName: string | null;
    fromDomain: string | null;
    fromFullDomain: string | null;
    senderIp: string | null;
    toAddr: string[];
    ccAddr: string[];
    bccAddr: string[];
    replyTo: string | null;
    inReplyTo: string | null;
    references: string | null;
    isReplyThread: boolean;
    subject: string;
    bodyText: string | null;
    bodyHtml: string | null;
    bodyPlain: string;
    urls: string[];
    urlDomains: string[];
    attachments: ParsedAttachment[];
    hasAttachment: boolean;
    headers: Record<string, string | string[]> | null;
    authHeaders: RawAuthHeaders;
    receivedAt: Date;
}

export interface ParsedAttachment {
    filename: string;
    mimeType: string;
    size: number;
    storagePath: string;
    sha256?: string;
}

export interface RawAuthHeaders {
    spf?: string | string[];
    dkim?: string | string[];
    dmarc?: string | string[];
    arc?: string | string[];
    authenticationResults?: string | string[];
}