import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import * as fs from 'fs/promises';
import * as path from 'path';
import { randomUUID } from 'crypto';

const ALLOWED_MIME_TYPES = [
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp',
];
const MAX_FILE_SIZE = 5 * 1024 * 1024; // 5MB

@Injectable()
export class StorageService {
  private readonly uploadDir: string;

  constructor(private config: ConfigService) {
    this.uploadDir =
      this.config.get<string>('UPLOAD_DIR') ??
      path.join(process.cwd(), 'uploads', 'avatars');
  }

  async ensureUploadDir(): Promise<void> {
    await fs.mkdir(this.uploadDir, { recursive: true });
  }

  validateFile(mimetype: string, size: number): void {
    if (!ALLOWED_MIME_TYPES.includes(mimetype)) {
      throw new Error(
        `Invalid file type. Allowed: ${ALLOWED_MIME_TYPES.join(', ')}`,
      );
    }
    if (size > MAX_FILE_SIZE) {
      throw new Error(`File too large. Maximum size: ${MAX_FILE_SIZE / 1024 / 1024}MB`);
    }
  }

  getExtension(mimetype: string): string {
    const map: Record<string, string> = {
      'image/jpeg': '.jpg',
      'image/png': '.png',
      'image/gif': '.gif',
      'image/webp': '.webp',
    };
    return map[mimetype] ?? '.jpg';
  }

  async saveFile(
    buffer: Buffer,
    mimetype: string,
    userId: number,
  ): Promise<string> {
    await this.ensureUploadDir();
    const ext = this.getExtension(mimetype);
    const filename = `avatar-${userId}-${randomUUID()}${ext}`;
    const filepath = path.join(this.uploadDir, filename);
    await fs.writeFile(filepath, buffer);
    return path.join('avatars', filename).replace(/\\/g, '/');
  }

  async deleteFile(relativePath: string): Promise<void> {
    const fullPath = path.join(
      process.cwd(),
      'uploads',
      relativePath.replace(/^\//, ''),
    );
    try {
      await fs.unlink(fullPath);
    } catch {
      // Ignore if file doesn't exist
    }
  }
}
