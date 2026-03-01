import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 16;
const AUTH_TAG_LENGTH = 16;
const SALT_LENGTH = 32;
const KEY_LENGTH = 32;

@Injectable()
export class EncryptionService {
  private readonly encryptionKey: Buffer;

  constructor(private config: ConfigService) {
    const secret =
      this.config.get<string>('ENCRYPTION_KEY') ?? process.env.ENCRYPTION_KEY;
    if (!secret || secret.length < 32) {
      const devKey = 'securemail-dev-encryption-key-min-32-chars!!';
      if (process.env.NODE_ENV === 'production') {
        throw new Error(
          'ENCRYPTION_KEY must be set and at least 32 characters for AES-256 in production',
        );
      }
      this.encryptionKey = crypto.scryptSync(devKey, 'securemail-salt', KEY_LENGTH);
    } else {
      this.encryptionKey = crypto.scryptSync(secret, 'securemail-salt', KEY_LENGTH);
    }
  }

  encrypt(plaintext: string): string {
    const iv = crypto.randomBytes(IV_LENGTH);
    const cipher = crypto.createCipheriv(ALGORITHM, this.encryptionKey, iv);
    let encrypted = cipher.update(plaintext, 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  }

  decrypt(ciphertext: string): string {
    const parts = ciphertext.split(':');
    if (parts.length !== 3) {
      throw new Error('Invalid encrypted data format');
    }
    const [ivHex, authTagHex, encrypted] = parts;
    const iv = Buffer.from(ivHex, 'hex');
    const authTag = Buffer.from(authTagHex, 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, this.encryptionKey, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  }
}
