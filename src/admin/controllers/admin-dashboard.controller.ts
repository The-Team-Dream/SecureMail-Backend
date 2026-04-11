import { Controller, Get, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiResponse, ApiTags } from '@nestjs/swagger';
import { ApiStandardErrorResponses } from 'src/common/swagger';
import { AdminDashboardService } from '../services/admin-dashboard.service';
import { TokenGuard } from '../../auth/guards/auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from 'generated/prisma/enums';

@ApiTags('admin/dashboard')
@ApiStandardErrorResponses()
@Controller('admin/dashboard')
@UseGuards(TokenGuard, RolesGuard)
@Roles(Role.ADMIN)
@ApiBearerAuth()
export class AdminDashboardController {
  constructor(private readonly service: AdminDashboardService) {}

  @Get()
  @ApiOperation({ summary: 'Dashboard summary' })
  @ApiResponse({ status: 200 })
  getDashboard() {
    return this.service.getDashboard();
  }
}
