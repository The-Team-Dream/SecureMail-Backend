// ─────────────────────────────────────────────────────────────────────────────
// mailboxes/emails/emails.controller.ts
//
// UPDATED:
//   1. Full Swagger documentation on every endpoint
//   2. Proper error messages with context (not generic "Bad Request")
//   3. Cloudinary attachment flow (StoredAttachment instead of disk paths)
//   4. @ApiConsumes('multipart/form-data') + @ApiBody on file upload endpoints 
// ─────────────────────────────────────────────────────────────────────────────

import {
  Controller,
  Get,
  Post,
  Patch,
  Delete,
  Body,
  Param,
  Query,
  Req,
  UseGuards,
  UseInterceptors,
  UploadedFiles,
  ParseIntPipe,
  BadRequestException,
  Res,
} from '@nestjs/common';
import { Response } from 'express';
import { FileFieldsInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import {
  ApiBearerAuth,
  ApiBody,
  ApiConsumes,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiResponse,
  ApiTags,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { ApiStandardErrorResponses } from 'src/common/swagger';
import { ApiErrorResponseDto } from 'src/common/swagger/api-error-response.dto';
import { EmailsService } from './emails.service';
import { TokenGuard } from '../../auth/guards/auth.guard';
import { PaginatedQueryDto } from './dto/paginated-query.dto';
import { SearchQueryDto } from './dto/search-query.dto';
import { MarkReadDto } from './dto/mark-read.dto';
import { ReportEmailDto } from './dto/report-email.dto';
import { ReclassifyEmailDto } from './dto/reclassify-email.dto';
import { ToggleStarDto } from './dto/toggle-star.dto';
import { SendEmailDto } from './dto/send-email.dto';
import { ReplyEmailDto } from './dto/reply-email.dto';
import { ForwardEmailDto } from './dto/forward-email.dto';
import { FolderType } from '@prisma/client';
import { EmailSendService } from './email-send.service';
import { StoredAttachment } from './attachment-storage.service';

// ── Shared Swagger error response descriptions ────────────────────────────────
const AUTH_ERRORS = {
  401: 'Missing or invalid Bearer token',
  403: 'You do not have permission to access this mailbox',
};

@ApiTags('Emails')
@ApiStandardErrorResponses()
@Controller('mailboxes/:mailboxId')
@UseGuards(TokenGuard)
@ApiBearerAuth()
@ApiParam({
  name:        'mailboxId',
  description: 'ID of the mailbox to operate on',
  example:     1,
  type:        Number,
})
export class EmailsController {
  constructor(
    private readonly emailsService:    EmailsService,
    private readonly emailSendService: EmailSendService,
  ) {}

  // ═══════════════════════════════════════════════════════════════════════════
  // READ — Folder listings
  // ═══════════════════════════════════════════════════════════════════════════

  @Get('inbox')
  @ApiOperation({
    summary:     'List inbox emails',
    description: 'Returns a paginated list of emails in the INBOX folder for the given mailbox.',
  })
  @ApiQuery({ name: 'page',  required: false, description: 'Page number (1-based)', example: 1 })
  @ApiQuery({ name: 'limit', required: false, description: 'Emails per page (max 100)', example: 20 })
  @ApiResponse({ status: 200, description: 'Paginated inbox email list returned successfully' })
  @ApiUnauthorizedResponse({ description: AUTH_ERRORS[401], type: ApiErrorResponseDto })
  @ApiResponse({ status: 404, description: 'Mailbox not found or does not belong to this user' })
  getInbox(
    @Req() req: { user: { id: number } },
    @Param('mailboxId', ParseIntPipe) mailboxId: number,
    @Query() query: PaginatedQueryDto,
  ) {
    return this.emailsService.listByFolder(
      req.user.id, mailboxId, FolderType.INBOX,
      query.page ?? 1, query.limit ?? 20,
    );
  }

  @Get('sent')
  @ApiOperation({
    summary:     'List sent emails',
    description: 'Returns a paginated list of emails in the SENT folder.',
  })
  @ApiQuery({ name: 'page',  required: false, example: 1 })
  @ApiQuery({ name: 'limit', required: false, example: 20 })
  @ApiResponse({ status: 200, description: 'Paginated sent email list returned successfully' })
  @ApiUnauthorizedResponse({ description: AUTH_ERRORS[401], type: ApiErrorResponseDto })
  @ApiResponse({ status: 404, description: 'Mailbox not found or does not belong to this user' })
  getSent(
    @Req() req: { user: { id: number } },
    @Param('mailboxId', ParseIntPipe) mailboxId: number,
    @Query() query: PaginatedQueryDto,
  ) {
    return this.emailsService.listByFolder(
      req.user.id, mailboxId, FolderType.SENT,
      query.page ?? 1, query.limit ?? 20,
    );
  }

  @Get('spam')
  @ApiOperation({
    summary:     'List spam emails',
    description: 'Returns a paginated list of emails classified as SPAM.',
  })
  @ApiQuery({ name: 'page',  required: false, example: 1 })
  @ApiQuery({ name: 'limit', required: false, example: 20 })
  @ApiResponse({ status: 200, description: 'Paginated spam email list returned successfully' })
  @ApiUnauthorizedResponse({ description: AUTH_ERRORS[401], type: ApiErrorResponseDto })
  @ApiResponse({ status: 404, description: 'Mailbox not found or does not belong to this user' })
  getSpam(
    @Req() req: { user: { id: number } },
    @Param('mailboxId', ParseIntPipe) mailboxId: number,
    @Query() query: PaginatedQueryDto,
  ) {
    return this.emailsService.listByFolder(
      req.user.id, mailboxId, FolderType.SPAM,
      query.page ?? 1, query.limit ?? 20,
    );
  }

  @Get('phishing')
  @ApiOperation({
    summary:     'List phishing emails',
    description: 'Returns a paginated list of emails classified as PHISHING by the security pipeline.',
  })
  @ApiQuery({ name: 'page',  required: false, example: 1 })
  @ApiQuery({ name: 'limit', required: false, example: 20 })
  @ApiResponse({ status: 200, description: 'Paginated phishing email list returned successfully' })
  @ApiUnauthorizedResponse({ description: AUTH_ERRORS[401], type: ApiErrorResponseDto })
  @ApiResponse({ status: 404, description: 'Mailbox not found or does not belong to this user' })
  getPhishing(
    @Req() req: { user: { id: number } },
    @Param('mailboxId', ParseIntPipe) mailboxId: number,
    @Query() query: PaginatedQueryDto,
  ) {
    return this.emailsService.listByFolder(
      req.user.id, mailboxId, FolderType.PHISHING,
      query.page ?? 1, query.limit ?? 20,
    );
  }

  @Get('starred')
  @ApiOperation({
    summary:     'List starred/flagged emails',
    description: 'Returns a paginated list of emails flagged as starred across all folders.',
  })
  @ApiQuery({ name: 'page',  required: false, example: 1 })
  @ApiQuery({ name: 'limit', required: false, example: 20 })
  @ApiResponse({ status: 200, description: 'Paginated starred email list returned successfully' })
  @ApiUnauthorizedResponse({ description: AUTH_ERRORS[401], type: ApiErrorResponseDto })
  @ApiResponse({ status: 404, description: 'Mailbox not found or does not belong to this user' })
  getStarred(
    @Req() req: { user: { id: number } },
    @Param('mailboxId', ParseIntPipe) mailboxId: number,
    @Query() query: PaginatedQueryDto,
  ) {
    return this.emailsService.listStarred(
      req.user.id, mailboxId,
      query.page ?? 1, query.limit ?? 20,
    );
  }

  @Get('malware')
  @ApiOperation({
    summary:     'List malware-quarantined emails',
    description: 'Returns a paginated list of emails classified as MALWARE and quarantined.',
  })
  @ApiQuery({ name: 'page',  required: false, example: 1 })
  @ApiQuery({ name: 'limit', required: false, example: 20 })
  @ApiResponse({ status: 200, description: 'Paginated malware email list returned successfully' })
  @ApiUnauthorizedResponse({ description: AUTH_ERRORS[401], type: ApiErrorResponseDto })
  @ApiResponse({ status: 404, description: 'Mailbox not found or does not belong to this user' })
  getMalware(
    @Req() req: { user: { id: number } },
    @Param('mailboxId', ParseIntPipe) mailboxId: number,
    @Query() query: PaginatedQueryDto,
  ) {
    return this.emailsService.listByFolder(
      req.user.id, mailboxId, FolderType.MALWARE,
      query.page ?? 1, query.limit ?? 20,
    );
  }

  @Get('trash')
  @ApiOperation({
    summary:     'List deleted emails',
    description: 'Returns a paginated list of emails moved to the TRASH folder.',
  })
  @ApiQuery({ name: 'page',  required: false, example: 1 })
  @ApiQuery({ name: 'limit', required: false, example: 20 })
  @ApiResponse({ status: 200, description: 'Paginated trash email list returned successfully' })
  @ApiUnauthorizedResponse({ description: AUTH_ERRORS[401], type: ApiErrorResponseDto })
  @ApiResponse({ status: 404, description: 'Mailbox not found or does not belong to this user' })
  getTrash(
    @Req() req: { user: { id: number } },
    @Param('mailboxId', ParseIntPipe) mailboxId: number,
    @Query() query: PaginatedQueryDto,
  ) {
    return this.emailsService.listByFolder(
      req.user.id, mailboxId, FolderType.TRASH,
      query.page ?? 1, query.limit ?? 20,
    );
  }

  @Get('search')
  @ApiOperation({
    summary:     'Search emails',
    description: 'Returns a paginated list of emails matching the search query in subject, from name, or from address.',
  })
  @ApiQuery({ name: 'q',     required: false, example: 'invoice' })
  @ApiQuery({ name: 'page',  required: false, example: 1 })
  @ApiQuery({ name: 'limit', required: false, example: 20 })
  @ApiResponse({ status: 200, description: 'Paginated search results returned successfully' })
  @ApiUnauthorizedResponse({ description: AUTH_ERRORS[401], type: ApiErrorResponseDto })
  @ApiResponse({ status: 404, description: 'Mailbox not found or does not belong to this user' })
  search(
    @Req() req: { user: { id: number } },
    @Param('mailboxId', ParseIntPipe) mailboxId: number,
    @Query() query: SearchQueryDto,
  ) {
    return this.emailsService.search(
      req.user.id, mailboxId, query.q,
      query.page ?? 1, query.limit ?? 20,
    );
  }

  @Get('reports')
  @ApiOperation({
    summary:     'List security reports/incidents',
    description: 'Returns a paginated list of security incidents detected in the mailbox (Phishing, Malware, Spam).',
  })
  @ApiQuery({ name: 'page',  required: false, example: 1 })
  @ApiQuery({ name: 'limit', required: false, example: 20 })
  @ApiResponse({ status: 200, description: 'Security reports returned successfully' })
  @ApiUnauthorizedResponse({ description: AUTH_ERRORS[401], type: ApiErrorResponseDto })
  @ApiResponse({ status: 404, description: 'Mailbox not found or does not belong to this user' })
  getReports(
    @Req() req: { user: { id: number } },
    @Param('mailboxId', ParseIntPipe) mailboxId: number,
    @Query() query: PaginatedQueryDto,
  ) {
    return this.emailsService.listReports(
      req.user.id, mailboxId,
      query.page ?? 1, query.limit ?? 20,
    );
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // READ — Single email
  // ═══════════════════════════════════════════════════════════════════════════

  @Get('emails/:id')
  @ApiOperation({
    summary:     'Get email details',
    description: 'Returns full email details including body, attachments, security verdict, and AI report.',
  })
  @ApiParam({ name: 'id', description: 'Email ID', example: 42, type: Number })
  @ApiResponse({ status: 200, description: 'Email details returned successfully' })
  @ApiUnauthorizedResponse({ description: AUTH_ERRORS[401], type: ApiErrorResponseDto })
  @ApiResponse({ status: 404, description: 'Email not found in this mailbox, or mailbox does not belong to this user' })
  findOne(
    @Req() req: { user: { id: number } },
    @Param('mailboxId', ParseIntPipe) mailboxId: number,
    @Param('id', ParseIntPipe) id: number,
  ) {
    return this.emailsService.findOne(req.user.id, mailboxId, id);
  }

  @Get('emails/:id/attachments/:attachmentId/download')
  @ApiOperation({
    summary:     'Download an email attachment',
    description: 'Downloads or redirects to the specified attachment.',
  })
  @ApiParam({ name: 'id', description: 'Email ID', type: Number })
  @ApiParam({ name: 'attachmentId', description: 'Attachment ID', type: Number })
  @ApiResponse({ status: 200, description: 'Streams the attachment file' })
  @ApiResponse({ status: 302, description: 'Redirects to the external storage URL (e.g. Cloudinary)' })
  @ApiUnauthorizedResponse({ description: AUTH_ERRORS[401], type: ApiErrorResponseDto })
  @ApiResponse({ status: 404, description: 'Attachment or Email not found' })
  async downloadAttachment(
    @Req() req: { user: { id: number } },
    @Param('mailboxId', ParseIntPipe) mailboxId: number,
    @Param('id', ParseIntPipe) id: number,
    @Param('attachmentId', ParseIntPipe) attachmentId: number,
    @Res() res: Response,
  ) {
    const result = await this.emailsService.downloadAttachment(req.user.id, mailboxId, id, attachmentId);
    
    if (result.type === 'redirect') {
      return res.redirect(result.url as string);
    }
    
    // Fallback (should not be reached due to service logic)
    throw new BadRequestException('Attachment download failed');
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // MUTATE — Email actions
  // ═══════════════════════════════════════════════════════════════════════════

  @Patch('emails/:id/read')
  @ApiOperation({
    summary:     'Mark email as read or unread',
    description: 'Updates the read status of an email. Pass `read: true` to mark as read, `read: false` to mark as unread.',
  })
  @ApiParam({ name: 'id', description: 'Email ID', example: 42, type: Number })
  @ApiResponse({ status: 200, description: 'Email read status updated successfully' })
  @ApiResponse({ status: 400, description: 'Invalid request body — `read` field must be a boolean' })
  @ApiUnauthorizedResponse({ description: AUTH_ERRORS[401], type: ApiErrorResponseDto })
  @ApiResponse({ status: 404, description: 'Email not found in this mailbox' })
  markRead(
    @Req() req: { user: { id: number } },
    @Param('mailboxId', ParseIntPipe) mailboxId: number,
    @Param('id', ParseIntPipe) id: number,
    @Body() dto: MarkReadDto,
  ) {
    return this.emailsService.markRead(req.user.id, mailboxId, id, dto.read);
  }

  @Patch('emails/:id/star')
  @ApiOperation({
    summary:     'Toggle email star (flag)',
    description: 'Updates the starred (flagged) status of an email.',
  })
  @ApiParam({ name: 'id', description: 'Email ID', example: 42, type: Number })
  @ApiResponse({ status: 200, description: 'Email star status updated successfully' })
  @ApiUnauthorizedResponse({ description: AUTH_ERRORS[401], type: ApiErrorResponseDto })
  @ApiResponse({ status: 404, description: 'Email not found in this mailbox' })
  toggleStar(
    @Req() req: { user: { id: number } },
    @Param('mailboxId', ParseIntPipe) mailboxId: number,
    @Param('id', ParseIntPipe) id: number,
    @Body() dto: ToggleStarDto,
  ) {
    return this.emailsService.toggleStar(req.user.id, mailboxId, id, dto.starred);
  }

  @Delete('emails/:id')
  @ApiOperation({
    summary:     'Delete email',
    description: 'Moves the email to TRASH. If already in TRASH, it is permanently deleted (soft-delete via deletedAt).',
  })
  @ApiParam({ name: 'id', description: 'Email ID', example: 42, type: Number })
  @ApiResponse({ status: 200, description: 'Email moved to trash or permanently deleted' })
  @ApiUnauthorizedResponse({ description: AUTH_ERRORS[401], type: ApiErrorResponseDto })
  @ApiResponse({ status: 404, description: 'Email not found in this mailbox' })
  delete(
    @Req() req: { user: { id: number } },
    @Param('mailboxId', ParseIntPipe) mailboxId: number,
    @Param('id', ParseIntPipe) id: number,
  ) {
    return this.emailsService.delete(req.user.id, mailboxId, id);
  }

  @Post('emails/:id/report')
  @ApiOperation({
    summary:     'Report email as spam or phishing',
    description: 'Manually reports an email. The email is moved to the corresponding folder and flagged for review.',
  })
  @ApiParam({ name: 'id', description: 'Email ID', example: 42, type: Number })
  @ApiResponse({ status: 200, description: 'Email reported and moved to the appropriate folder' })
  @ApiResponse({ status: 400, description: 'Invalid report type — must be "spam" or "phishing"' })
  @ApiUnauthorizedResponse({ description: AUTH_ERRORS[401], type: ApiErrorResponseDto })
  @ApiResponse({ status: 404, description: 'Email not found in this mailbox' })
  report(
    @Req() req: { user: { id: number } },
    @Param('mailboxId', ParseIntPipe) mailboxId: number,
    @Param('id', ParseIntPipe) id: number,
    @Body() dto: ReportEmailDto,
  ) {
    return this.emailsService.report(req.user.id, mailboxId, id, dto.type);
  }

  @Patch('emails/:id/reclassify')
  @ApiOperation({
    summary:     'Reclassify email (move to correct folder)',
    description: 'Manually overrides the security classification and moves the email to the specified folder. Use this to correct false positives or false negatives.',
  })
  @ApiParam({ name: 'id', description: 'Email ID', example: 42, type: Number })
  @ApiResponse({ status: 200, description: 'Email reclassified and moved to the target folder' })
  @ApiResponse({ status: 400, description: 'Invalid folder type — must be one of: inbox, sent, spam, phishing, trash' })
  @ApiUnauthorizedResponse({ description: AUTH_ERRORS[401], type: ApiErrorResponseDto })
  @ApiResponse({ status: 404, description: 'Email not found in this mailbox' })
  reclassify(
    @Req() req: { user: { id: number } },
    @Param('mailboxId', ParseIntPipe) mailboxId: number,
    @Param('id', ParseIntPipe) id: number,
    @Body() dto: ReclassifyEmailDto,
  ) {
    return this.emailsService.reclassify(req.user.id, mailboxId, id, dto.folder);
  }

  @Post('emails/:id/scan')
  @ApiOperation({
    summary:     'Scan email for security threats',
    description: 'Manually triggers a security scan for the specified email. This re-runs the full security pipeline.',
  })
  @ApiParam({ name: 'id', description: 'Email ID', example: 42, type: Number })
  @ApiResponse({ status: 200, description: 'Email scanned successfully' })
  @ApiUnauthorizedResponse({ description: AUTH_ERRORS[401], type: ApiErrorResponseDto })
  @ApiResponse({ status: 404, description: 'Email not found in this mailbox' })
  scanEmail(
    @Req() req: { user: { id: number } },
    @Param('mailboxId', ParseIntPipe) mailboxId: number,
    @Param('id', ParseIntPipe) id: number,
  ) {
    return this.emailsService.scanEmail(req.user.id, mailboxId, id);
  }

  @Post('scan-all')
  @ApiOperation({
    summary:     'Scan all emails in mailbox',
    description: 'Manually triggers a security scan for all emails currently in the mailbox. This re-runs the security pipeline for every email.',
  })
  @ApiResponse({ status: 200, description: 'All emails scanned successfully' })
  @ApiUnauthorizedResponse({ description: AUTH_ERRORS[401], type: ApiErrorResponseDto })
  @ApiResponse({ status: 404, description: 'Mailbox not found' })
  scanAllEmails(
    @Req() req: { user: { id: number } },
    @Param('mailboxId', ParseIntPipe) mailboxId: number,
  ) {
    return this.emailsService.scanAllEmails(req.user.id, mailboxId);
  }

  @Get('scan-progress')
  @ApiOperation({
    summary:     'Get bulk scan progress',
    description: 'Returns the progress of the asynchronous bulk scanning operation.',
  })
  @ApiResponse({ status: 200, description: 'Progress returned successfully' })
  @ApiUnauthorizedResponse({ description: AUTH_ERRORS[401], type: ApiErrorResponseDto })
  @ApiResponse({ status: 404, description: 'Mailbox not found' })
  getScanProgress(
    @Req() req: { user: { id: number } },
    @Param('mailboxId', ParseIntPipe) mailboxId: number,
  ) {
    return this.emailsService.getScanProgress(req.user.id, mailboxId);
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SEND — Compose, Reply, Forward
  // ═══════════════════════════════════════════════════════════════════════════

  @Post('send')
  @UseInterceptors(
    FileFieldsInterceptor(
      [{ name: 'attachments', maxCount: 10 }],
      { storage: memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } },
    ),
  )
  @ApiOperation({
    summary:     'Send a new email',
    description: [
      'Queues a new email for sending via the configured mailbox provider (Gmail / Outlook / SMTP).',
      '',
      'Accepts `multipart/form-data` to support file attachments.',
      'Attachments are uploaded to Cloudinary and the CDN URLs are stored.',
      '',
      '**Limits:** Max 10 attachments, 10MB each.',
    ].join('\n'),
  })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    description: 'Email data + optional attachments',
    schema: {
      type:       'object',
      required:   ['to', 'subject'],
      properties: {
        to:          { type: 'string',  format: 'email', example: 'recipient@example.com' },
        cc:          { type: 'string',  description: 'Comma-separated CC addresses', example: 'cc@example.com' },
        bcc:         { type: 'string',  description: 'Comma-separated BCC addresses' },
        subject:     { type: 'string',  example: 'Hello from SecureMail' },
        bodyText:    { type: 'string',  description: 'Plain text body' },
        bodyHtml:    { type: 'string',  description: 'HTML body (used instead of bodyText if provided)' },
        attachments: { type: 'array', items: { type: 'string', format: 'binary' }, description: 'Up to 10 files, max 10MB each' },
      },
    },
  })
  @ApiResponse({ status: 202, description: 'Email successfully queued for sending' })
  @ApiResponse({ status: 400, description: 'Validation error — missing required fields, invalid email address, or attachment too large' })
  @ApiUnauthorizedResponse({ description: AUTH_ERRORS[401], type: ApiErrorResponseDto })
  @ApiResponse({ status: 404, description: 'Mailbox not found or does not belong to this user' })
  async send(
    @Req() req: { user: { id: number } },
    @Param('mailboxId', ParseIntPipe) mailboxId: number,
    @Body() dto: SendEmailDto,
    @UploadedFiles() files?: { attachments?: Express.Multer.File[] },
  ) {
    const attachments = await this.emailSendService.prepareAttachments(
      files?.attachments ?? [],
    );
    try {
      return await this.emailSendService.queueSend(req.user.id, mailboxId, dto, attachments);
    } catch (e) {
      await this.emailSendService.cleanupAttachments(attachments);
      throw e;
    }
  }

  @Post('emails/:id/reply')
  @UseInterceptors(
    FileFieldsInterceptor(
      [{ name: 'attachments', maxCount: 10 }],
      { storage: memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } },
    ),
  )
  @ApiOperation({
    summary:     'Reply to an email',
    description: 'Queues a reply to the specified email. Automatically sets In-Reply-To and References headers for proper threading.',
  })
  @ApiParam({ name: 'id', description: 'ID of the email to reply to', example: 42, type: Number })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    description: 'Reply content + optional attachments',
    schema: {
      type:       'object',
      required:   ['content'],
      properties: {
        content:     { type: 'string', example: 'Thanks for your message!' },
        bodyHtml:    { type: 'string', description: 'HTML body (overrides content if provided)' },
        attachments: { type: 'array', items: { type: 'string', format: 'binary' } },
      },
    },
  })
  @ApiResponse({ status: 202, description: 'Reply successfully queued for sending' })
  @ApiResponse({ status: 400, description: 'Validation error — content is required and cannot be empty' })
  @ApiUnauthorizedResponse({ description: AUTH_ERRORS[401], type: ApiErrorResponseDto })
  @ApiResponse({ status: 404, description: 'Email or mailbox not found' })
  async reply(
    @Req() req: { user: { id: number } },
    @Param('mailboxId', ParseIntPipe) mailboxId: number,
    @Param('id', ParseIntPipe) id: number,
    @Body() dto: ReplyEmailDto,
    @UploadedFiles() files?: { attachments?: Express.Multer.File[] },
  ) {
    const attachments = await this.emailSendService.prepareAttachments(
      files?.attachments ?? [],
    );
    try {
      return await this.emailSendService.queueReply(
        req.user.id, mailboxId, id, dto.content, dto.bodyHtml, attachments,
      );
    } catch (e) {
      await this.emailSendService.cleanupAttachments(attachments);
      throw e;
    }
  }

  @Post('emails/:id/forward')
  @UseInterceptors(
    FileFieldsInterceptor(
      [{ name: 'attachments', maxCount: 10 }],
      { storage: memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } },
    ),
  )
  @ApiOperation({
    summary:     'Forward an email',
    description: 'Forwards an existing email to a new recipient. Prepends "Fwd:" to the subject and includes the original message body.',
  })
  @ApiParam({ name: 'id', description: 'ID of the email to forward', example: 42, type: Number })
  @ApiConsumes('multipart/form-data')
  @ApiBody({
    description: 'Forward recipient + optional message + optional attachments',
    schema: {
      type:       'object',
      required:   ['to'],
      properties: {
        to:          { type: 'string', format: 'email', example: 'colleague@example.com' },
        message:     { type: 'string', description: 'Additional message to prepend to the forwarded email' },
        attachments: { type: 'array', items: { type: 'string', format: 'binary' } },
      },
    },
  })
  @ApiResponse({ status: 202, description: 'Forward successfully queued for sending' })
  @ApiResponse({ status: 400, description: 'Validation error — recipient email address is required and must be valid' })
  @ApiUnauthorizedResponse({ description: AUTH_ERRORS[401], type: ApiErrorResponseDto })
  @ApiResponse({ status: 404, description: 'Email or mailbox not found' })
  async forward(
    @Req() req: { user: { id: number } },
    @Param('mailboxId', ParseIntPipe) mailboxId: number,
    @Param('id', ParseIntPipe) id: number,
    @Body() dto: ForwardEmailDto,
    @UploadedFiles() files?: { attachments?: Express.Multer.File[] },
  ) {
    const attachments = await this.emailSendService.prepareAttachments(
      files?.attachments ?? [],
    );
    try {
      return await this.emailSendService.queueForward(
        req.user.id, mailboxId, id, dto.to, dto.message, attachments,
      );
    } catch (e) {
      await this.emailSendService.cleanupAttachments(attachments);
      throw e;
    }
  }
}
