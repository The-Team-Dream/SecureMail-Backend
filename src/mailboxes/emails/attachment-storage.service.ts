// ─────────────────────────────────────────────────────────────────────────────
// mailboxes/emails/attachment-storage.service.ts
//
// UPDATED: Local disk storage → Cloudinary cloud storage
//
// Why Cloudinary?
//   - Files survive server restarts / redeployments
//   - No disk space management needed
//   - Built-in CDN for fast retrieval
//   - Free tier: 25GB storage + 25GB bandwidth/month
//
// Why Multer Memory Storage?
//   - File lands in RAM as Buffer — no temp file written to disk
//   - Buffer passed directly to Cloudinary upload stream
//   - Zero disk I/O, zero cleanup needed for temp files
//
// Flow:
//   Multer (RAM Buffer) → upload_stream → Cloudinary → returns { url, public_id }
//   public_id stored in DB as storagePath (used for deletion)
//   url stored in DB as storageUrl (used for retrieval)
//
// ENV vars required:
//   CLOUDINARY_CLOUD_NAME=xxx
//   CLOUDINARY_API_KEY=xxx
//   CLOUDINARY_API_SECRET=xxx
//
// Install: pnpm add cloudinary
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { v2 as cloudinary } from 'cloudinary'
import type { UploadApiResponse } from 'cloudinary'
const MAX_FILE_SIZE       = 10 * 1024 * 1024; // 10MB per file
const MAX_TOTAL_ATTACHMENTS = 10;

export interface StoredAttachment { 
  url:        string;   // Cloudinary CDN URL — for retrieval
  publicId:   string;   // Cloudinary public_id — for deletion
  filename:   string;   // Original sanitized filename
  mimeType:   string;   // MIME type
}

@Injectable()
export class AttachmentStorageService {
  private readonly logger = new Logger(AttachmentStorageService.name);

  constructor(private readonly config: ConfigService) {
    // Configure Cloudinary once at service init using env vars
    cloudinary.config({
      cloud_name:  this.config.getOrThrow<string>('CLOUDINARY_CLOUD_NAME'),
      api_key:     this.config.getOrThrow<string>('CLOUDINARY_API_KEY'),
      api_secret:  this.config.getOrThrow<string>('CLOUDINARY_API_SECRET'),
    });
  }

  // ── Upload multiple attachments from Multer memory storage ──────────────────
  // Each file.buffer is streamed directly to Cloudinary — no disk write.
  async saveAttachments(
    files: Express.Multer.File[],
  ): Promise<StoredAttachment[]> {
    if (files.length > MAX_TOTAL_ATTACHMENTS) {
      throw new BadRequestException(
        `Too many attachments. Maximum allowed is ${MAX_TOTAL_ATTACHMENTS} files per email.`,
      );
    }

    // Validate sizes before uploading any file
    for (const file of files) {
      if (file.size > MAX_FILE_SIZE) {
        throw new BadRequestException(
          `File "${file.originalname}" exceeds the 10MB size limit. Please compress or remove it.`,
        );
      }
    }

    // Upload all files in parallel — Cloudinary handles concurrency
    const results = await Promise.all(
      files.map(file => this.uploadToCloudinary(file)),
    );

    return results;
  }

  // ── Upload a single file Buffer to Cloudinary via upload_stream ─────────────
  private uploadToCloudinary(file: Express.Multer.File): Promise<StoredAttachment> {
    return new Promise((resolve, reject) => {
      const safeName = (file.originalname || 'attachment')
        .replace(/[^a-zA-Z0-9.\-_]/g, '_');

      // upload_stream accepts a Buffer and streams it to Cloudinary
      // resource_type: 'raw' → handles all file types (not just images)
      // folder: 'securemail/attachments' → organizes files in Cloudinary dashboard
      const stream = cloudinary.uploader.upload_stream(
        {
          resource_type: 'raw',
          folder:        'securemail/attachments',
          public_id:     `${Date.now()}_${safeName}`,
          use_filename:  true,
          overwrite:     false,
        },
        (error, result: UploadApiResponse | undefined) => {
          if (error || !result) {
            this.logger.error(`Cloudinary upload failed for ${safeName}`, error);
            reject(new BadRequestException(
              `Failed to upload attachment "${file.originalname}". Please try again.`,
            ));
            return;
          }

          resolve({
            url:      result.secure_url,
            publicId: result.public_id,
            filename: safeName,
            mimeType: file.mimetype || 'application/octet-stream',
          });
        },
      );

      // End the stream with the file buffer from Multer memory storage
      stream.end(file.buffer);
    });
  }

  // ── Read attachment by Cloudinary URL (returns Buffer for email sending) ─────
  // Used by EmailSendProcessor when attaching files to outgoing emails
  async readAttachment(url: string): Promise<Buffer> {
    const response = await fetch(url);
    if (!response.ok) {
      throw new BadRequestException(
        `Could not retrieve attachment. The file may have been deleted or is temporarily unavailable.`,
      );
    }
    const arrayBuffer = await response.arrayBuffer();
    return Buffer.from(arrayBuffer);
  }

  // ── Delete a single attachment from Cloudinary ───────────────────────────────
  // Called on cleanup after failed sends or when email is permanently deleted
  async deleteAttachment(publicId: string): Promise<void> {
    try {
      await cloudinary.uploader.destroy(publicId, { resource_type: 'raw' });
    } catch (err) {
      // Log but don't throw — deletion failure shouldn't break the main flow
      this.logger.warn(`Failed to delete Cloudinary attachment ${publicId}`, err);
    }
  }

  // ── Delete multiple attachments (batch cleanup) ───────────────────────────────
  async cleanupAttachments(
    attachments: Array<{ publicId: string }>,
  ): Promise<void> {
    if (!attachments?.length) return;
    await Promise.allSettled(
      attachments.map(a => this.deleteAttachment(a.publicId)),
    );
  }

  // ── Legacy compatibility: cleanupPaths (used by EmailSendService) ─────────────
  // Maps old { path } shape to new { publicId } shape for backward compat
  async cleanupPaths(
    attachments: Array<{ url: string }>,
  ): Promise<void> {
    // In the new Cloudinary flow, 'path' field stores the publicId
    await this.cleanupAttachments(
      attachments.map(a => ({ publicId: a.url })),
    );
  }
}
