import { Controller, Get, Param, Query, UseGuards } from '@nestjs/common';
import {
  ApiBearerAuth,
  ApiOperation,
  ApiParam,
  ApiResponse,
  ApiTags,
} from '@nestjs/swagger';
import { ApiStandardErrorResponses } from 'src/common/swagger';
import { AdminAuditService } from '../services/admin-audit.service';
import { TokenGuard } from '../../auth/guards/auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from '@prisma/client';
import { AdminAuditLogsQueryDto } from '../dto/audit-logs-query.dto';

@ApiTags('admin/audit-logs')
@ApiStandardErrorResponses()
@Controller('admin/audit-logs')
@UseGuards(TokenGuard, RolesGuard)
@Roles(Role.ADMIN)
@ApiBearerAuth()
export class AdminAuditController {
  constructor(private readonly service: AdminAuditService) { }

  @Get()
  @ApiOperation({ summary: 'Paginated audit logs with filters' })
  @ApiResponse({ status: 200 })
  findAll(@Query() query: AdminAuditLogsQueryDto) {
    return this.service.findAll(
      query.page ?? 1,
      query.limit ?? 20,
      query.action,
      query.targetType,
      query.fromDate,
      query.toDate,
    );
  }

  @Get(':adminId')
  @ApiParam({ name: 'adminId' })
  @ApiOperation({ summary: 'Audit logs for specific admin' })
  @ApiResponse({ status: 200 })
  findByAdmin(
    @Param('adminId') adminId: string,
    @Query() query: AdminAuditLogsQueryDto,
  ) {
    return this.service.findByAdmin(
      +adminId,
      query.page ?? 1,
      query.limit ?? 20,
    );
  }
}
