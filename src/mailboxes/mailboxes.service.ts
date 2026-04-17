import {
  BadRequestException,
  Injectable,
  NotFoundException,
} from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { EncryptionService } from '../common/encryption/encryption.service';
import { EmailSyncService } from './email-sync.service';
import { GmailProvider } from './providers/gmail.provider';
import { OutlookProvider } from './providers/outlook.provider';
import { ImapProvider } from './providers/imap.provider';
import { ConnectGmailDto } from './dto/connect-gmail.dto';
import { ConnectOutlookDto } from './dto/connect-outlook.dto';
import { ConnectImapDto } from './dto/connect-imap.dto';
import { UpdateMailboxDto } from './dto/update-mailbox.dto';
import { EmailProviders } from '@prisma/client';
import { ImapAuthType, SmtpAuthType } from '@prisma/client';

@Injectable()
export class MailboxesService {
  constructor(
    private prisma: PrismaService,
    private encryption: EncryptionService,
    private emailSyncService: EmailSyncService,
    private gmailProvider: GmailProvider,
    private outlookProvider: OutlookProvider,
    private imapProvider: ImapProvider,
  ) { }

  async findAll(userId: number) {
    const mailboxes = await this.prisma.mailBox.findMany({
      where: { userId },
      include: {
        folders: true,
        oauthToken: true,
        imapConfig: true,
        _count: { select: { emails: true } },
      },
      orderBy: { createdAt: 'desc' },
    });
    return mailboxes.map((mb) => {
      const { imapConfig, oauthToken, ...rest } = mb as typeof mb & {
        imapConfig?: unknown;
        oauthToken?: unknown;
      };
      return {
        ...rest,
        hasCredentials: !!(imapConfig || oauthToken),
      };
    });
  }

  async getGmailAuthUrl(userId: number, redirectUri: string) {
    const state = Buffer.from(JSON.stringify({ userId })).toString('base64url');
    return {
      url: this.gmailProvider.getAuthUrl(redirectUri, state),
    };
  }

  async connectGmail(userId: number, dto: ConnectGmailDto) {
    const { tokens, email } = await this.gmailProvider.exchangeCodeForTokens(
      dto.code,
      dto.redirectUri,
    );
    const existing = await this.prisma.mailBox.findFirst({
      where: { userId, emailAddress: email, provider: EmailProviders.GMAIL },
    });
    if (existing) {
      await this.prisma.oauthToken.update({
        where: { mailBoxId: existing.id },
        data: {
          accessTokenEncrypted: this.encryption.encrypt(tokens.accessToken),
          refreshTokenEncrypted: this.encryption.encrypt(tokens.refreshToken),
          expiresAt: tokens.expiresAt,
        },
      });
      await this.prisma.mailBox.update({
        where: { id: existing.id },
        data: { lastSyncedAt: new Date(), isActive: true },
      });
      return this.findOne(userId, existing.id);
    }
    const mailBox = await this.prisma.mailBox.create({
      data: {
        userId,
        provider: EmailProviders.GMAIL,
        emailAddress: email,
        displayName: email.split('@')[0],
        oauthToken: {
          create: {
            provider: 'gmail',
            accessTokenEncrypted: this.encryption.encrypt(tokens.accessToken),
            refreshTokenEncrypted: this.encryption.encrypt(tokens.refreshToken),
            expiresAt: tokens.expiresAt,
            scope: 'gmail.readonly gmail.modify',
          },
        },
      },
      include: { folders: true },
    });
    return mailBox;
  }

  async getOutlookAuthUrl(userId: number, redirectUri: string) {
    const state = Buffer.from(JSON.stringify({ userId })).toString('base64url');
    return {
      url: this.outlookProvider.getAuthUrl(redirectUri, state),
    };
  }

  async connectOutlook(userId: number, dto: ConnectOutlookDto) {
    const { tokens, email } =
      await this.outlookProvider.exchangeCodeForTokens(
        dto.code,
        dto.redirectUri,
      );
    const existing = await this.prisma.mailBox.findFirst({
      where: { userId, emailAddress: email, provider: EmailProviders.OUTLOOK },
    });
    if (existing) {
      await this.prisma.oauthToken.update({
        where: { mailBoxId: existing.id },
        data: {
          accessTokenEncrypted: this.encryption.encrypt(tokens.accessToken),
          refreshTokenEncrypted: this.encryption.encrypt(tokens.refreshToken),
          expiresAt: tokens.expiresAt,
        },
      });
      await this.prisma.mailBox.update({
        where: { id: existing.id },
        data: { lastSyncedAt: new Date(), isActive: true },
      });
      return this.findOne(userId, existing.id);
    }
    const mailBox = await this.prisma.mailBox.create({
      data: {
        userId,
        provider: EmailProviders.OUTLOOK,
        emailAddress: email,
        displayName: email.split('@')[0],
        oauthToken: {
          create: {
            provider: 'outlook',
            accessTokenEncrypted: this.encryption.encrypt(tokens.accessToken),
            refreshTokenEncrypted: this.encryption.encrypt(tokens.refreshToken),
            expiresAt: tokens.expiresAt,
            scope: 'Mail.Read Mail.ReadWrite',
          },
        },
      },
      include: { folders: true },
    });
    return mailBox;
  }

  private inferSmtpFromImap(imapHost: string): { host: string; port: number } {
    const h = imapHost.toLowerCase();
    if (h.includes('gmail') || h.includes('google')) return { host: 'smtp.gmail.com', port: 587 };
    if (h.includes('outlook') || h.includes('office365') || h.includes('live')) return { host: 'smtp.office365.com', port: 587 };
    if (h.includes('yahoo')) return { host: 'smtp.mail.yahoo.com', port: 587 };
    return { host: imapHost.replace(/^imap\./, 'smtp.'), port: 587 };
  }

  async connectImap(userId: number, dto: ConnectImapDto) {
    const canConnect = await this.imapProvider.testConnection({
      host: dto.host,
      port: dto.port,
      secure: dto.secure ?? true,
      auth: { user: dto.email, pass: dto.password },
    });
    if (!canConnect) {
      throw new BadRequestException('Failed to connect to IMAP server');
    }
    const smtp =
      dto.smtpHost && dto.smtpPort
        ? { host: dto.smtpHost, port: dto.smtpPort }
        : this.inferSmtpFromImap(dto.host);
    const existing = await this.prisma.mailBox.findFirst({
      where: { userId, emailAddress: dto.email, provider: EmailProviders.CUSTOM },
      include: { smtpConfig: true },
    });
    if (existing) {
      await this.prisma.imapConfig.update({
        where: { mailBoxId: existing.id },
        data: {
          host: dto.host,
          port: dto.port,
          secure: dto.secure ?? true,
          passwordEncrypted: this.encryption.encrypt(dto.password),
        },
      });
      if (existing.smtpConfig) {
        await this.prisma.smtpConfig.update({
          where: { mailBoxId: existing.id },
          data: {
            host: smtp.host,
            port: smtp.port,
            secure: dto.secure ?? true,
            passwordEncrypted: this.encryption.encrypt(dto.password),
          },
        });
      } else {
        await this.prisma.smtpConfig.create({
          data: {
            mailBoxId: existing.id,
            host: smtp.host,
            port: smtp.port,
            secure: dto.secure ?? true,
            authType: SmtpAuthType.PASSWORD,
            passwordEncrypted: this.encryption.encrypt(dto.password),
          },
        });
      }
      await this.prisma.mailBox.update({
        where: { id: existing.id },
        data: {
          displayName: dto.displayName,
          lastSyncedAt: new Date(),
          isActive: true,
        },
      });
      return this.findOne(userId, existing.id);
    }
    const mailBox = await this.prisma.mailBox.create({
      data: {
        userId,
        provider: EmailProviders.CUSTOM,
        emailAddress: dto.email,
        displayName: dto.displayName,
        imapConfig: {
          create: {
            host: dto.host,
            port: dto.port,
            secure: dto.secure ?? true,
            authType: ImapAuthType.PASSWORD,
            passwordEncrypted: this.encryption.encrypt(dto.password),
          },
        },
        smtpConfig: {
          create: {
            host: smtp.host,
            port: smtp.port,
            secure: dto.secure ?? true,
            authType: SmtpAuthType.PASSWORD,
            passwordEncrypted: this.encryption.encrypt(dto.password),
          },
        },
      },
      include: { folders: true, imapConfig: true, smtpConfig: true },
    });
    return this.findOne(userId, mailBox.id);
  }

  async findOne(userId: number, id: number) {
    const mailBox = await this.prisma.mailBox.findFirst({
      where: { id, userId },
      include: {
        folders: true,
        oauthToken: true,
        imapConfig: true,
        _count: { select: { emails: true } },
      },
    });
    if (!mailBox) {
      throw new NotFoundException('Mailbox not found');
    }
    const { imapConfig, oauthToken, ...rest } = mailBox as typeof mailBox & {
      imapConfig?: { passwordEncrypted?: string };
      oauthToken?: unknown;
    };
    return {
      ...rest,
      hasCredentials: !!(imapConfig?.passwordEncrypted ?? oauthToken),
    };
  }

  async update(userId: number, id: number, dto: UpdateMailboxDto) {
    await this.findOne(userId, id);
    return this.prisma.mailBox.update({
      where: { id },
      data: dto,
    });
  }

  async remove(userId: number, id: number) {
    await this.findOne(userId, id);
    await this.prisma.mailBox.delete({ where: { id } });
    return { message: 'Mailbox disconnected successfully' };
  }

  async getGmailTokens(mailBoxId: number) {
    const token = await this.prisma.oauthToken.findUnique({
      where: { mailBoxId },
    });
    if (!token || token.provider !== 'gmail') return null;
    const now = new Date();
    if (token.expiresAt <= new Date(now.getTime() + 5 * 60 * 1000)) {
      const refreshed = await this.gmailProvider.refreshTokens(
        token.accessTokenEncrypted,
        token.refreshTokenEncrypted,
      );
      await this.prisma.oauthToken.update({
        where: { mailBoxId },
        data: {
          accessTokenEncrypted: this.encryption.encrypt(refreshed.accessToken),
          refreshTokenEncrypted: this.encryption.encrypt(refreshed.refreshToken),
          expiresAt: refreshed.expiresAt,
        },
      });
      return {
        accessToken: refreshed.accessToken,
        refreshToken: refreshed.refreshToken,
      };
    }
    return {
      accessToken: this.encryption.decrypt(token.accessTokenEncrypted),
      refreshToken: this.encryption.decrypt(token.refreshTokenEncrypted),
    };
  }

  async getOutlookTokens(mailBoxId: number) {
    const token = await this.prisma.oauthToken.findUnique({
      where: { mailBoxId },
    });
    if (!token || token.provider !== 'outlook') return null;
    const now = new Date();
    if (token.expiresAt <= new Date(now.getTime() + 5 * 60 * 1000)) {
      const refreshed = await this.outlookProvider.refreshTokens(
        token.refreshTokenEncrypted,
      );
      await this.prisma.oauthToken.update({
        where: { mailBoxId },
        data: {
          accessTokenEncrypted: this.encryption.encrypt(refreshed.accessToken),
          refreshTokenEncrypted: this.encryption.encrypt(refreshed.refreshToken),
          expiresAt: refreshed.expiresAt,
        },
      });
      return {
        accessToken: refreshed.accessToken,
        refreshToken: refreshed.refreshToken,
      };
    }
    return {
      accessToken: this.encryption.decrypt(token.accessTokenEncrypted),
      refreshToken: this.encryption.decrypt(token.refreshTokenEncrypted),
    };
  }

  async triggerSync(userId: number, mailBoxId: number) {
    await this.findOne(userId, mailBoxId);
    await this.emailSyncService.scheduleSync(mailBoxId);
    return { message: 'Sync scheduled' };
  }

  async getImapCredentials(mailBoxId: number) {
    const mb = await this.prisma.mailBox.findUnique({
      where: { id: mailBoxId },
      include: { imapConfig: true },
    });
    if (!mb?.imapConfig?.passwordEncrypted || !mb.emailAddress) return null;
    return {
      host: mb.imapConfig.host,
      port: mb.imapConfig.port,
      secure: mb.imapConfig.secure,
      auth: {
        user: mb.emailAddress,
        pass: this.encryption.decrypt(mb.imapConfig.passwordEncrypted),
      },
    };
  }
}
