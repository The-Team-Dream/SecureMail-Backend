import { Controller, Get, Param, Query, Req, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiParam,
  ApiQuery,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { ApiStandardErrorResponses } from 'src/common/swagger';
import { AnalyticsService } from './analytics.service';
import { TokenGuard } from '../auth/guards/auth.guard';
import { ActivityPeriodDto } from './dto/activity-period.dto';

@ApiTags('analytics')
@ApiStandardErrorResponses()
@Controller('analytics')
@UseGuards(TokenGuard)
@ApiBearerAuth()
export class AnalyticsController {
  constructor(private readonly analyticsService: AnalyticsService) {}

  @Get('overview')
  @ApiOperation({ summary: 'Get overall stats across all mailboxes' })
  @ApiResponse({ status: 200, description: 'Overview statistics' })
  getOverview(@Req() req: { user: { id: number } }) {
    return this.analyticsService.getOverview(req.user.id);
  }

  @Get('mailboxes/:mailboxId')
  @ApiParam({ name: 'mailboxId', description: 'Mailbox ID', type: Number })
  @ApiOperation({ summary: 'Get per-mailbox statistics' })
  @ApiResponse({ status: 200, description: 'Mailbox statistics' })
  @ApiResponse({ status: 404, description: 'Mailbox not found' })
  getMailboxStats(
    @Req() req: { user: { id: number } },
    @Param('mailboxId') mailboxId: string,
  ) {
    return this.analyticsService.getMailboxStats(req.user.id, +mailboxId);
  }

  @Get('activity')
  @ApiOperation({ summary: 'Get email activity over time' })
  @ApiQuery({ name: 'period', enum: ['daily', 'weekly', 'monthly'], required: false })
  @ApiResponse({ status: 200, description: 'Activity data by period' })
  getActivity(
    @Req() req: { user: { id: number } },
    @Query() dto: ActivityPeriodDto,
  ) {
    return this.analyticsService.getActivity(
      req.user.id,
      dto.period ?? 'daily',
    );
  }
}
