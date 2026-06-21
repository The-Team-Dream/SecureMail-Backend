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
        emails: {
          select: {
            attachments: {
              select: { size: true }
            }
          }
        }
      },
      orderBy: { createdAt: 'asc' },
    });

    return mailboxes.map((mb) => {
      const { imapConfig, oauthToken, emails, ...rest } = mb as any;
      
      // Calculate storage used from emails' attachments
      let storageUsed = 0;
      for (const email of emails) {
        for (const att of email.attachments) {
          storageUsed += att.size;
        }
      }

      return {
        ...rest,
        hasCredentials: !!(imapConfig || oauthToken),
        storageUsed,
        storageLimit: 20 * 1024 * 1024 * 1024, // 20 GB default
      };
    });
  }

  async getGmailAuthUrl(userId: number, redirectUri: string, clientType = 'web') {
    const state = Buffer.from(JSON.stringify({ userId, clientType })).toString('base64url');
    return {
      url: this.gmailProvider.getAuthUrl(redirectUri, state),
    };
  }

  async connectGmail(userId: number, dto: ConnectGmailDto) {
    console.log(`[MailboxesService] connectGmail started for user ${userId}`);
    console.log(`[MailboxesService] Code: ${dto.code}`);
    console.log(`[MailboxesService] RedirectUri: ${dto.redirectUri}`);
    
    const { tokens, email } = await this.gmailProvider.exchangeCodeForTokens(
      dto.code,
      dto.redirectUri,
    );
    
    console.log(`[MailboxesService] Successfully exchanged code for tokens for ${email}`);

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
        displayName: dto.displayName || email.split('@')[0],
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
    
    // Trigger immediate sync
    await this.emailSyncService.scheduleSync(mailBox.id);

    return mailBox;

  }  

  async getOutlookAuthUrl(userId: number, redirectUri: string, clientType = 'web') {
    const state = Buffer.from(JSON.stringify({ userId, clientType })).toString('base64url');
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
        displayName: dto.displayName || email.split('@')[0],
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
    
    // Trigger immediate sync
    await this.emailSyncService.scheduleSync(mailBox.id);

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

    // Trigger immediate sync
    await this.emailSyncService.scheduleSync(mailBox.id);

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

    // ── Calculate Storage Usage ────────────────────────── uyvzepxffzulwwdf
    const storageStats = await this.prisma.attachment.aggregate({
      where: {
        email: {
          mailBoxId: id,
        },
      },
      _sum: {
        size: true,
      },
    });

    const storageUsed = storageStats._sum.size || 0;
    const storageLimit = 20 * 1024 * 1024 * 1024; // 20 GB default limit

    const { imapConfig, oauthToken, ...rest } = mailBox as typeof mailBox & {
      imapConfig?: { passwordEncrypted?: string };
      oauthToken?: unknown;
    };
    return {
      ...rest,
      hasCredentials: !!(imapConfig?.passwordEncrypted ?? oauthToken),
      storageUsed,
      storageLimit,
    };
  }

  async update(userId: number, id: number, dto: UpdateMailboxDto) {
    await this.findOne(userId, id);
    await this.prisma.mailBox.update({
      where: { id },
      data: dto,
    });
    return this.findOne(userId, id);
  }

  async remove(userId: number, id: number) {
    const mailBox = await this.prisma.mailBox.findFirst({
      where: { id, userId },
      include: { oauthToken: true },
    });
    if (!mailBox) {
      throw new NotFoundException('Mailbox not found');
    }

    if (mailBox.provider === EmailProviders.GMAIL && mailBox.oauthToken) {
      await this.gmailProvider.revokeToken(mailBox.oauthToken.refreshTokenEncrypted);
    }

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

  async markRemoteRead(mailboxId: number, messageId: string, read: boolean, folderRemoteId: string) {
    const mailbox = await this.prisma.mailBox.findUnique({
      where: { id: mailboxId },
      include: { oauthToken: true, imapConfig: true },
    });
    if (!mailbox) return;

    try {
      if (mailbox.provider === EmailProviders.GMAIL && mailbox.oauthToken) {
        const tokens = await this.getGmailTokens(mailboxId);
        if (tokens) {
          const gmail = await this.gmailProvider.getGmailClient(
            this.encryption.encrypt(tokens.accessToken),
            this.encryption.encrypt(tokens.refreshToken),
          );
          await this.gmailProvider.modifyLabels(
            gmail,
            'me',
            messageId,
            read ? [] : ['UNREAD'],
            read ? ['UNREAD'] : [],
          );
        }
      } else if (mailbox.provider === EmailProviders.OUTLOOK && mailbox.oauthToken) {
        const tokens = await this.getOutlookTokens(mailboxId);
        if (tokens) {
          const client = this.outlookProvider.getGraphClient(tokens.accessToken);
          await this.outlookProvider.updateMessage(client, messageId, { isRead: read });
        }
      } else if (mailbox.provider === EmailProviders.CUSTOM && mailbox.imapConfig) {
        const creds = await this.getImapCredentials(mailboxId);
        if (creds) {
          const client = await this.imapProvider.connect(creds);
          try {
            // For IMAP, messageId usually corresponds to UID if we saved it correctly,
            // but our sync process uses envelope.messageId as messageId in DB.
            // Wait, we need the UID to update flags in IMAP.
            // If the messageId in DB is not the UID, we have a problem.
            // Let's assume for IMAP we might need a search or we saved UID in some way.
            // Actually, in imap.provider.ts, messageId was: msg.envelope.messageId ?? `imap-${mailBox.id}-${folder.id}-${msg.uid}`
            // This is not reliable for updates. 
            // TODO: For IMAP, we should ideally store the UID.
            // For now, we'll skip IMAP remote mark read or try to find by messageId.
            const lock = await client.getMailboxLock(folderRemoteId);
            try {
               const search = await client.search({ header: { 'Message-ID': messageId } }, { uid: true });
               if (search && search.length > 0) { 
                 await this.imapProvider.setMessageFlags(client, folderRemoteId, search[0], ['\\Seen'], read ? 'add' : 'remove');
               }
            } finally {
              lock.release();
            }
          } finally {
            await client.logout();
          }
        }
      }
    } catch (err) {
      console.error(`[MailboxesService] Failed to mark remote email as read: ${err}`);
    }
  }
  async deleteRemoteEmail(mailboxId: number, messageId: string, folderRemoteId: string) {
    const mailbox = await this.prisma.mailBox.findUnique({
      where: { id: mailboxId },
      include: { oauthToken: true, imapConfig: true },
    });
    if (!mailbox) return;

    try {
      if (mailbox.provider === EmailProviders.GMAIL && mailbox.oauthToken) {
        const tokens = await this.getGmailTokens(mailboxId);
        if (tokens) {
          const gmail = await this.gmailProvider.getGmailClient(
            this.encryption.encrypt(tokens.accessToken),
            this.encryption.encrypt(tokens.refreshToken),
          );
          await this.gmailProvider.trashMessage(gmail, 'me', messageId);
        }
      } else if (mailbox.provider === EmailProviders.OUTLOOK && mailbox.oauthToken) {
        const tokens = await this.getOutlookTokens(mailboxId);
        if (tokens) {
          const client = this.outlookProvider.getGraphClient(tokens.accessToken);
          await this.outlookProvider.trashMessage(client, messageId);
        }
      } else if (mailbox.provider === EmailProviders.CUSTOM && mailbox.imapConfig) {
        const creds = await this.getImapCredentials(mailboxId);
        if (creds) {
          const client = await this.imapProvider.connect(creds);
          try {
            await this.imapProvider.trashMessage(client, folderRemoteId, messageId);
          } finally {
            await client.logout();
          }
        }
      }
    } catch (err) {
      console.error(`[MailboxesService] Failed to delete remote email: ${err}`);
    }
  }
}
