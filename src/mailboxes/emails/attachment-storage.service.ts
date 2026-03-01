import { Injectable } from '@nestjs/common';
import * as fs from 'fs/promises';
import * as path from 'path';
import { randomUUID } from 'crypto';

const MAX_FILE_SIZE = 10 * 1024 * 1024; // 10MB per file
const MAX_TOTAL_ATTACHMENTS = 10;

@Injectable()
export class AttachmentStorageService {
  private readonly baseDir = path.join(process.cwd(), 'uploads', 'attachments');

  async saveAttachments(
    files: Express.Multer.File[],
  ): Promise<Array<{ path: string; filename: string; mimeType: string }>> {
    if (files.length > MAX_TOTAL_ATTACHMENTS) {
      throw new Error(`Maximum ${MAX_TOTAL_ATTACHMENTS} attachments allowed`);
    }

    const batchId = randomUUID();
    const batchDir = path.join(this.baseDir, batchId);
    await fs.mkdir(batchDir, { recursive: true });

    const result: Array<{ path: string; filename: string; mimeType: string }> = [];

    for (const file of files) {
      if (file.size > MAX_FILE_SIZE) {
        await this.cleanupBatch(batchDir);
        throw new Error(`File ${file.originalname} exceeds 10MB limit`);
      }

      const safeName = (file.originalname || 'attachment').replace(/[^a-zA-Z0-9.-]/g, '_');
      const filepath = path.join(batchDir, safeName);
      await fs.writeFile(filepath, file.buffer);

      result.push({
        path: filepath,
        filename: safeName,
        mimeType: file.mimetype || 'application/octet-stream',
      });
    }

    return result;
  }

  async readAttachment(filePath: string): Promise<Buffer> {
    return fs.readFile(filePath);
  }

  async cleanupBatch(batchDir: string): Promise<void> {
    try {
      await fs.rm(batchDir, { recursive: true });
    } catch {
      // Ignore
    }
  }

  async cleanupPaths(
    attachmentPaths: Array<{ path: string }>,
  ): Promise<void> {
    const dirs = new Set<string>();
    for (const { path: p } of attachmentPaths) {
      dirs.add(path.dirname(p));
    }
    for (const dir of dirs) {
      await this.cleanupBatch(dir);
    }
  }
}
