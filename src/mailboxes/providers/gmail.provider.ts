import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { google, gmail_v1 } from 'googleapis';
import { EncryptionService } from '../../common/encryption/encryption.service';

const GMAIL_SCOPES = [
  'https://www.googleapis.com/auth/gmail.readonly',
  'https://www.googleapis.com/auth/gmail.modify',
  'https://www.googleapis.com/auth/userinfo.email',
  'https://www.googleapis.com/auth/userinfo.profile',
];

export interface GmailTokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: Date;
}

export interface GmailMessageSummary {
  id: string;
  threadId: string;
  labelIds: string[];
  snippet: string;
  internalDate: string;
}

@Injectable()
export class GmailProvider {
  private readonly clientId: string;
  private readonly clientSecret: string;

  constructor(
    private config: ConfigService,
    private encryption: EncryptionService,
  ) {
    this.clientId = this.config.get<string>('GOOGLE_CLIENT_ID') ?? '';
    this.clientSecret = this.config.get<string>('GOOGLE_CLIENT_SECRET') ?? '';
  }

  getAuthUrl(redirectUri: string, state?: string): string {
    const oauth2Client = new google.auth.OAuth2(
      this.clientId,
      this.clientSecret,
      redirectUri,
    );
    return oauth2Client.generateAuthUrl({
      access_type: 'offline',
      prompt: 'consent',
      scope: GMAIL_SCOPES,
      state: state ?? undefined,
    });
  }

  async exchangeCodeForTokens(
    code: string,
    redirectUri: string,
  ): Promise<{ tokens: GmailTokens; email: string }> {
    const oauth2Client = new google.auth.OAuth2(
      this.clientId,
      this.clientSecret,
      redirectUri,
    );
    console.log(`[GmailProvider] Requesting tokens from Google with code...`);
    const { tokens } = await oauth2Client.getToken(code);
    console.log(`[GmailProvider] Tokens received from Google.`);

    if (!tokens.access_token || !tokens.refresh_token) {
      throw new Error('Invalid token response from Google');
    }
    const expiresAt = tokens.expiry_date
      ? new Date(tokens.expiry_date)
      : new Date(Date.now() + 3600 * 1000);

    const oauth2 = google.oauth2({ version: 'v2', auth: oauth2Client });
    oauth2Client.setCredentials(tokens);
    const { data } = await oauth2.userinfo.get();
    const email = data.email ?? '';

    return {
      tokens: {
        accessToken: tokens.access_token,
        refreshToken: tokens.refresh_token,
        expiresAt,
      },
      email,
    };
  }

  async refreshTokens(
    accessTokenEncrypted: string,
    refreshTokenEncrypted: string,
  ): Promise<GmailTokens> {
    const refreshToken = this.encryption.decrypt(refreshTokenEncrypted);
    const oauth2Client = new google.auth.OAuth2(
      this.clientId,
      this.clientSecret,
    );
    oauth2Client.setCredentials({ refresh_token: refreshToken });
    const { credentials } = await oauth2Client.refreshAccessToken();
    if (!credentials.access_token || !credentials.refresh_token) {
      throw new Error('Failed to refresh tokens');
    }
    const expiresAt = credentials.expiry_date
      ? new Date(credentials.expiry_date)
      : new Date(Date.now() + 3600 * 1000);
    return {
      accessToken: credentials.access_token,
      refreshToken: credentials.refresh_token,
      expiresAt,
    };
  }

  async getGmailClient(
    accessTokenEncrypted: string,
    refreshTokenEncrypted: string,
  ): Promise<gmail_v1.Gmail> {
    const accessToken = this.encryption.decrypt(accessTokenEncrypted);
    const oauth2Client = new google.auth.OAuth2(
      this.clientId,
      this.clientSecret,
    );
    oauth2Client.setCredentials({
      access_token: accessToken,
      refresh_token: this.encryption.decrypt(refreshTokenEncrypted),
    });
    return google.gmail({ version: 'v1', auth: oauth2Client });
  }

  async listMessages(
    gmail: gmail_v1.Gmail,
    userId: string,
    labelIds: string[],
    maxResults = 50,
    pageToken?: string,
  ): Promise<{ messages: GmailMessageSummary[]; nextPageToken?: string }> {
    const res = await gmail.users.messages.list({
      userId,
      labelIds,
      maxResults,
      pageToken,
    });
    const messages = (res.data.messages ?? []).map((m) => ({
      id: m.id!,
      threadId: m.threadId ?? '',
      labelIds: m.labelIds ?? [],
      snippet: m.snippet ?? '',
      internalDate: String(m.internalDate ?? ''),
    }));
    return {
      messages,
      nextPageToken: res.data.nextPageToken ?? undefined,
    };
  }

  async getMessage(
    gmail: gmail_v1.Gmail,
    userId: string,
    messageId: string,
  ): Promise<gmail_v1.Schema$Message> {
    const res = await gmail.users.messages.get({
      userId,
      id: messageId,
      format: 'full',
    });
    return res.data;
  }

  async getAttachment(
    gmail: gmail_v1.Gmail,
    userId: string,
    messageId: string,
    attachmentId: string,
  ): Promise<gmail_v1.Schema$MessagePartBody> {
    const res = await gmail.users.messages.attachments.get({
      userId,
      messageId,
      id: attachmentId,
    });
    return res.data;
  }

  getLabelMapping(): Record<string, string> {
    return {
      INBOX: 'INBOX',
      SENT: 'SENT',
      SPAM: 'SPAM',
      TRASH: 'TRASH',
    };
  }
}
