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
} from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { ApiStandardErrorResponses } from 'src/common/swagger';
import { MailboxesService } from './mailboxes.service';
import { AnalyticsService } from '../analytics/analytics.service';
import { TokenGuard } from '../auth/guards/auth.guard';
import { ConnectGmailDto } from './dto/connect-gmail.dto';
import { ConnectOutlookDto } from './dto/connect-outlook.dto';
import { ConnectImapDto } from './dto/connect-imap.dto';
import { UpdateMailboxDto } from './dto/update-mailbox.dto';

@ApiTags('mailboxes')
@ApiStandardErrorResponses()
@Controller('mailboxes')
@UseGuards(TokenGuard)
@ApiBearerAuth()
export class MailboxesController {
  constructor(
    private readonly mailboxesService: MailboxesService,
    private readonly analyticsService: AnalyticsService,
  ) {}

  @Get()
  @ApiOperation({ summary: 'List all connected mailboxes' })
  @ApiResponse({ status: 200, description: 'List of mailboxes' })
  findAll(@Req() req: { user: { id: number } }) {
    return this.mailboxesService.findAll(req.user.id);
  }

  @Get('gmail/auth-url')
  @ApiOperation({ summary: 'Get Gmail OAuth2 authorization URL' })
  @ApiResponse({ status: 200, description: 'Authorization URL for Gmail OAuth' })
  getGmailAuthUrl(
    @Req() req: { user: { id: number } },
    @Query('redirectUri') redirectUri: string,
  ) {
    return this.mailboxesService.getGmailAuthUrl(
      req.user.id,
      redirectUri || `${process.env.FRONTEND_URL ?? 'http://localhost:3000'}/mailboxes/gmail/callback`,
    );
  }

  @Post('gmail')
  @ApiOperation({ summary: 'Connect Gmail via OAuth2' })
  @ApiResponse({ status: 201, description: 'Gmail mailbox connected' })
  @ApiResponse({ status: 400, description: 'Invalid authorization code' })
  connectGmail(
    @Req() req: { user: { id: number } },
    @Body() dto: ConnectGmailDto,
  ) {
    return this.mailboxesService.connectGmail(req.user.id, dto);
  }

  @Get('outlook/auth-url')
  @ApiOperation({ summary: 'Get Outlook OAuth2 authorization URL' })
  @ApiResponse({ status: 200, description: 'Authorization URL for Outlook OAuth' })
  getOutlookAuthUrl(
    @Req() req: { user: { id: number } },
    @Query('redirectUri') redirectUri: string,
  ) {
    return this.mailboxesService.getOutlookAuthUrl(
      req.user.id,
      redirectUri || `${process.env.FRONTEND_URL ?? 'http://localhost:3000'}/mailboxes/outlook/callback`,
    );
  }

  @Post('outlook')
  @ApiOperation({ summary: 'Connect Outlook via OAuth2' })
  @ApiResponse({ status: 201, description: 'Outlook mailbox connected' })
  @ApiResponse({ status: 400, description: 'Invalid authorization code' })
  connectOutlook(
    @Req() req: { user: { id: number } },
    @Body() dto: ConnectOutlookDto,
  ) {
    return this.mailboxesService.connectOutlook(req.user.id, dto);
  }

  @Post('imap')
  @ApiOperation({ summary: 'Connect custom email via IMAP' })
  @ApiResponse({ status: 201, description: 'IMAP mailbox connected' })
  @ApiResponse({ status: 400, description: 'Connection test failed' })
  connectImap(
    @Req() req: { user: { id: number } },
    @Body() dto: ConnectImapDto,
  ) {
    return this.mailboxesService.connectImap(req.user.id, dto);
  }

  @Get(':id/reports')
  @ApiParam({ name: 'id', description: 'Mailbox ID' })
  @ApiOperation({ summary: 'Get flagged emails report (spam + phishing)' })
  @ApiResponse({ status: 200, description: 'List of flagged emails with classification details' })
  @ApiResponse({ status: 404, description: 'Mailbox not found' })
  getReports(@Req() req: { user: { id: number } }, @Param('id') id: string) {
    return this.analyticsService.getFlaggedEmailsReport(req.user.id, +id);
  }

  @Get(':id')
  @ApiParam({ name: 'id', description: 'Mailbox ID' })
  @ApiOperation({ summary: 'Get mailbox by ID' })
  @ApiResponse({ status: 200, description: 'Mailbox details' })
  @ApiResponse({ status: 404, description: 'Mailbox not found' })
  findOne(@Req() req: { user: { id: number } }, @Param('id') id: string) {
    return this.mailboxesService.findOne(req.user.id, +id);
  }

  @Patch(':id')
  @ApiOperation({ summary: 'Update mailbox settings' })
  @ApiResponse({ status: 200, description: 'Mailbox updated' })
  @ApiResponse({ status: 404, description: 'Mailbox not found' })
  update(
    @Req() req: { user: { id: number } },
    @Param('id') id: string,
    @Body() dto: UpdateMailboxDto,
  ) {
    return this.mailboxesService.update(req.user.id, +id, dto);
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Disconnect mailbox' })
  @ApiResponse({ status: 200, description: 'Mailbox disconnected' })
  @ApiResponse({ status: 404, description: 'Mailbox not found' })
  remove(@Req() req: { user: { id: number } }, @Param('id') id: string) {
    return this.mailboxesService.remove(req.user.id, +id);
  }

  @Post(':id/sync')
  @ApiOperation({ summary: 'Trigger manual sync for a mailbox' })
  @ApiResponse({ status: 200, description: 'Sync scheduled' })
  @ApiResponse({ status: 404, description: 'Mailbox not found' })
  triggerSync(@Req() req: { user: { id: number } }, @Param('id') id: string) {
    return this.mailboxesService.triggerSync(req.user.id, +id);
  }
}
