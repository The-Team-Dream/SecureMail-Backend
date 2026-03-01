import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { Client } from '@microsoft/microsoft-graph-client';
import { EncryptionService } from '../../common/encryption/encryption.service';
import 'isomorphic-fetch';

const OUTLOOK_SCOPES = [
  'openid',
  'profile',
  'email',
  'offline_access',
  'Mail.Read',
  'Mail.ReadWrite',
  'Mail.Send',
];

export interface OutlookTokens {
  accessToken: string;
  refreshToken: string;
  expiresAt: Date;
}

@Injectable()
export class OutlookProvider {
  private readonly clientId: string;
  private readonly clientSecret: string;
  private readonly tenantId: string;

  constructor(
    private config: ConfigService,
    private encryption: EncryptionService,
  ) {
    this.clientId = this.config.get<string>('MICROSOFT_CLIENT_ID') ?? '';
    this.clientSecret = this.config.get<string>('MICROSOFT_CLIENT_SECRET') ?? '';
    this.tenantId = this.config.get<string>('MICROSOFT_TENANT_ID') ?? 'common';
  }

  getAuthUrl(redirectUri: string, state?: string): string {
    const params = new URLSearchParams({
      client_id: this.clientId,
      response_type: 'code',
      redirect_uri: redirectUri,
      scope: OUTLOOK_SCOPES.join(' '),
      response_mode: 'query',
      ...(state && { state }),
    });
    return `https://login.microsoftonline.com/${this.tenantId}/oauth2/v2.0/authorize?${params.toString()}`;
  }

  async exchangeCodeForTokens(
    code: string,
    redirectUri: string,
  ): Promise<{ tokens: OutlookTokens; email: string }> {
    const url = `https://login.microsoftonline.com/${this.tenantId}/oauth2/v2.0/token`;
    const body = new URLSearchParams({
      client_id: this.clientId,
      client_secret: this.clientSecret,
      code,
      redirect_uri: redirectUri,
      grant_type: 'authorization_code',
    });
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Microsoft token exchange failed: ${err}`);
    }
    const data = (await res.json()) as {
      access_token: string;
      refresh_token: string;
      expires_in: number;
    };
    const expiresAt = new Date(Date.now() + data.expires_in * 1000);

    const meRes = await fetch('https://graph.microsoft.com/v1.0/me', {
      headers: { Authorization: `Bearer ${data.access_token}` },
    });
    const me = (await meRes.json()) as { mail?: string; userPrincipalName?: string };
    const email = me.mail ?? me.userPrincipalName ?? '';

    return {
      tokens: {
        accessToken: data.access_token,
        refreshToken: data.refresh_token,
        expiresAt,
      },
      email,
    };
  }

  async refreshTokens(
    refreshTokenEncrypted: string,
  ): Promise<OutlookTokens> {
    const refreshToken = this.encryption.decrypt(refreshTokenEncrypted);
    const url = `https://login.microsoftonline.com/${this.tenantId}/oauth2/v2.0/token`;
    const body = new URLSearchParams({
      client_id: this.clientId,
      client_secret: this.clientSecret,
      refresh_token: refreshToken,
      grant_type: 'refresh_token',
    });
    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });
    if (!res.ok) {
      const err = await res.text();
      throw new Error(`Microsoft token refresh failed: ${err}`);
    }
    const data = (await res.json()) as {
      access_token: string;
      refresh_token?: string;
      expires_in: number;
    };
    const expiresAt = new Date(Date.now() + data.expires_in * 1000);
    return {
      accessToken: data.access_token,
      refreshToken: data.refresh_token ?? refreshToken,
      expiresAt,
    };
  }

  getGraphClient(accessToken: string): Client {
    return Client.init({
      authProvider: (done) => done(null, accessToken),
    });
  }

  async listMessages(
    client: Client,
    folderId: string,
    top = 50,
    skipToken?: string,
  ): Promise<{
    messages: Array<{ id: string; subject: string; receivedDateTime: string }>;
    nextLink?: string;
  }> {
    let url = `/me/mailFolders/${folderId}/messages?$top=${top}&$select=id,subject,from,toRecipients,ccRecipients,bccRecipients,body,bodyPreview,receivedDateTime,isRead,flag,hasAttachments`;
    if (skipToken) {
      url += `&$skiptoken=${encodeURIComponent(skipToken)}`;
    }
    const res = await client.api(url).get();
    const messages = (res.value ?? []).map((m: { id: string; subject: string; receivedDateTime: string }) => ({
      id: m.id,
      subject: m.subject ?? '',
      receivedDateTime: m.receivedDateTime ?? '',
    }));
    return {
      messages,
      nextLink: res['@odata.nextLink'],
    };
  }

  async getMessage(client: Client, messageId: string) {
    return client
      .api(`/me/messages/${messageId}`)
      .select('id,subject,from,toRecipients,ccRecipients,bccRecipients,body,bodyPreview,receivedDateTime,isRead,flag,hasAttachments')
      .get();
  }

  getFolderMapping(): Record<string, string> {
    return {
      inbox: 'inbox',
      sentitems: 'sentitems',
      junkemail: 'junkemail',
    };
  }
}
