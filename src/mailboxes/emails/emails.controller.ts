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
} from '@nestjs/common';
import { FileFieldsInterceptor } from '@nestjs/platform-express';
import { memoryStorage } from 'multer';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { EmailsService } from './emails.service';
import { TokenGuard } from '../../auth/guards/auth.guard';
import { PaginatedQueryDto } from './dto/paginated-query.dto';
import { MarkReadDto } from './dto/mark-read.dto';
import { ReportEmailDto } from './dto/report-email.dto';
import { ReclassifyEmailDto } from './dto/reclassify-email.dto';
import { SendEmailDto } from './dto/send-email.dto';
import { ReplyEmailDto } from './dto/reply-email.dto';
import { ForwardEmailDto } from './dto/forward-email.dto';
import { FolderType } from 'generated/prisma/enums';
import { EmailSendService } from './email-send.service';

@ApiTags('emails')
@Controller('mailboxes/:mailboxId')
@UseGuards(TokenGuard)
@ApiBearerAuth()
@ApiParam({ name: 'mailboxId', description: 'Mailbox ID' })
export class EmailsController {
  constructor(
    private readonly emailsService: EmailsService,
    private readonly emailSendService: EmailSendService,
  ) {}

  @Get('inbox')
  @ApiOperation({ summary: 'Get paginated inbox emails' })
  @ApiResponse({ status: 200, description: 'Paginated list of inbox emails' })
  getInbox(
    @Req() req: { user: { id: number } },
    @Param('mailboxId') mailboxId: string,
    @Query() query: PaginatedQueryDto,
  ) {
    return this.emailsService.listByFolder(
      req.user.id,
      +mailboxId,
      FolderType.INBOX,
      query.page ?? 1,
      query.limit ?? 20,
    );
  }

  @Get('sent')
  @ApiOperation({ summary: 'Get paginated sent emails' })
  @ApiResponse({ status: 200, description: 'Paginated list of sent emails' })
  getSent(
    @Req() req: { user: { id: number } },
    @Param('mailboxId') mailboxId: string,
    @Query() query: PaginatedQueryDto,
  ) {
    return this.emailsService.listByFolder(
      req.user.id,
      +mailboxId,
      FolderType.SENT,
      query.page ?? 1,
      query.limit ?? 20,
    );
  }

  @Get('spam')
  @ApiOperation({ summary: 'Get paginated spam emails' })
  @ApiResponse({ status: 200, description: 'Paginated list of spam emails' })
  getSpam(
    @Req() req: { user: { id: number } },
    @Param('mailboxId') mailboxId: string,
    @Query() query: PaginatedQueryDto,
  ) {
    return this.emailsService.listByFolder(
      req.user.id,
      +mailboxId,
      FolderType.SPAM,
      query.page ?? 1,
      query.limit ?? 20,
    );
  }

  @Get('phishing')
  @ApiOperation({ summary: 'Get paginated phishing emails' })
  @ApiResponse({ status: 200, description: 'Paginated list of phishing emails' })
  getPhishing(
    @Req() req: { user: { id: number } },
    @Param('mailboxId') mailboxId: string,
    @Query() query: PaginatedQueryDto,
  ) {
    return this.emailsService.listByFolder(
      req.user.id,
      +mailboxId,
      FolderType.PHISHING,
      query.page ?? 1,
      query.limit ?? 20,
    );
  }

  @Get('emails/:id')
  @ApiParam({ name: 'id', description: 'Email ID' })
  @ApiOperation({ summary: 'Get full email details with attachments' })
  @ApiResponse({ status: 200, description: 'Email details' })
  @ApiResponse({ status: 404, description: 'Email not found' })
  findOne(
    @Req() req: { user: { id: number } },
    @Param('mailboxId') mailboxId: string,
    @Param('id') id: string,
  ) {
    return this.emailsService.findOne(req.user.id, +mailboxId, +id);
  }

  @Patch('emails/:id/read')
  @ApiOperation({ summary: 'Mark email as read or unread' })
  @ApiResponse({ status: 200, description: 'Email updated' })
  @ApiResponse({ status: 404, description: 'Email not found' })
  markRead(
    @Req() req: { user: { id: number } },
    @Param('mailboxId') mailboxId: string,
    @Param('id') id: string,
    @Body() dto: MarkReadDto,
  ) {
    return this.emailsService.markRead(
      req.user.id,
      +mailboxId,
      +id,
      dto.read,
    );
  }

  @Delete('emails/:id')
  @ApiOperation({ summary: 'Delete email (move to trash or soft delete)' })
  @ApiResponse({ status: 200, description: 'Email deleted' })
  @ApiResponse({ status: 404, description: 'Email not found' })
  delete(
    @Req() req: { user: { id: number } },
    @Param('mailboxId') mailboxId: string,
    @Param('id') id: string,
  ) {
    return this.emailsService.delete(req.user.id, +mailboxId, +id);
  }

  @Post('emails/:id/report')
  @ApiOperation({ summary: 'Report email as spam or phishing' })
  @ApiResponse({ status: 200, description: 'Email reported' })
  @ApiResponse({ status: 404, description: 'Email not found' })
  report(
    @Req() req: { user: { id: number } },
    @Param('mailboxId') mailboxId: string,
    @Param('id') id: string,
    @Body() dto: ReportEmailDto,
  ) {
    return this.emailsService.report(
      req.user.id,
      +mailboxId,
      +id,
      dto.type,
    );
  }

  @Patch('emails/:id/reclassify')
  @ApiOperation({ summary: 'Manually move email to correct folder' })
  @ApiResponse({ status: 200, description: 'Email reclassified' })
  @ApiResponse({ status: 404, description: 'Email not found' })
  reclassify(
    @Req() req: { user: { id: number } },
    @Param('mailboxId') mailboxId: string,
    @Param('id') id: string,
    @Body() dto: ReclassifyEmailDto,
  ) {
    return this.emailsService.reclassify(
      req.user.id,
      +mailboxId,
      +id,
      dto.folder,
    );
  }

  @Post('send')
  @UseInterceptors(
    FileFieldsInterceptor(
      [{ name: 'attachments', maxCount: 10 }],
      {
        storage: memoryStorage(),
        limits: { fileSize: 10 * 1024 * 1024 },
      },
    ),
  )
  @ApiOperation({ summary: 'Send new email (supports multipart/form-data with attachments)' })
  @ApiResponse({ status: 202, description: 'Email queued for sending' })
  @ApiResponse({ status: 400, description: 'Invalid request' })
  @ApiResponse({ status: 404, description: 'Mailbox not found' })
  async send(
    @Req() req: { user: { id: number } },
    @Param('mailboxId') mailboxId: string,
    @Body() dto: SendEmailDto,
    @UploadedFiles() files?: { attachments?: Express.Multer.File[] },
  ) {
    const attachmentPaths = await this.emailSendService.prepareAttachments(
      files?.attachments ?? [],
    );
    try {
      return await this.emailSendService.queueSend(
        req.user.id,
        +mailboxId,
        dto,
        attachmentPaths,
      );
    } catch (e) {
      await this.emailSendService.cleanupAttachments(attachmentPaths);
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
  @ApiOperation({ summary: 'Reply to email' })
  @ApiResponse({ status: 202, description: 'Reply queued for sending' })
  @ApiResponse({ status: 404, description: 'Email not found' })
  async reply(
    @Req() req: { user: { id: number } },
    @Param('mailboxId') mailboxId: string,
    @Param('id') id: string,
    @Body() dto: ReplyEmailDto,
    @UploadedFiles() files?: { attachments?: Express.Multer.File[] },
  ) {
    const attachmentPaths = await this.emailSendService.prepareAttachments(
      files?.attachments ?? [],
    );
    try {
      return await this.emailSendService.queueReply(
        req.user.id,
        +mailboxId,
        +id,
        dto.content,
        dto.bodyHtml,
        attachmentPaths,
      );
    } catch (e) {
      await this.emailSendService.cleanupAttachments(attachmentPaths);
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
  @ApiOperation({ summary: 'Forward email' })
  @ApiResponse({ status: 202, description: 'Forward queued for sending' })
  @ApiResponse({ status: 404, description: 'Email not found' })
  async forward(
    @Req() req: { user: { id: number } },
    @Param('mailboxId') mailboxId: string,
    @Param('id') id: string,
    @Body() dto: ForwardEmailDto,
    @UploadedFiles() files?: { attachments?: Express.Multer.File[] },
  ) {
    const attachmentPaths = await this.emailSendService.prepareAttachments(
      files?.attachments ?? [],
    );
    try {
      return await this.emailSendService.queueForward(
        req.user.id,
        +mailboxId,
        +id,
        dto.to,
        dto.message,
        attachmentPaths,
      );
    } catch (e) {
      await this.emailSendService.cleanupAttachments(attachmentPaths);
      throw e;
    }
  }
}
