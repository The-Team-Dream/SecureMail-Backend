import { Controller, Get, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { AdminStatsService } from '../services/admin-stats.service';
import { TokenGuard } from '../../auth/guards/auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from 'generated/prisma/enums';

@ApiTags('admin/stats')
@Controller('admin/stats')
@UseGuards(TokenGuard, RolesGuard)
@Roles(Role.ADMIN)
@ApiBearerAuth()
export class AdminStatsController {
  constructor(private readonly service: AdminStatsService) {}

  @Get('overview')
  @ApiOperation({ summary: 'System overview stats' })
  @ApiResponse({ status: 200 })
  getOverview() {
    return this.service.getOverview();
  }

  @Get('activity')
  @ApiOperation({ summary: 'Activity over time (30 days)' })
  @ApiResponse({ status: 200 })
  getActivity() {
    return this.service.getActivity();
  }
}
