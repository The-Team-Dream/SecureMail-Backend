import {
  Controller,
  Get,
  Post,
  Delete,
  Param,
  Query,
  Body,
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
import { AdminNotificationsService } from '../services/admin-notifications.service';
import { TokenGuard } from '../../auth/guards/auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from 'generated/prisma/enums';
import { BroadcastNotificationDto } from '../dto/broadcast-notification.dto';
import { AdminPaginatedDto } from '../dto/common.dto';

@ApiTags('admin/notifications')
@ApiStandardErrorResponses()
@Controller('admin/notifications')
@UseGuards(TokenGuard, RolesGuard)
@Roles(Role.ADMIN)
@ApiBearerAuth()
export class AdminNotificationsController {
  constructor(private readonly service: AdminNotificationsService) {}

  @Get()
  @ApiOperation({ summary: 'Paginated list of all notifications' })
  @ApiResponse({ status: 200 })
  findAll(@Query() query: AdminPaginatedDto) {
    return this.service.findAll(query.page ?? 1, query.limit ?? 20);
  }

  @Post('broadcast')
  @ApiOperation({ summary: 'Broadcast notification to users' })
  @ApiResponse({ status: 201 })
  broadcast(
    @Req() req: { user: { id: number } },
    @Body() dto: BroadcastNotificationDto,
  ) {
    return this.service.broadcast(
      req.user.id,
      dto.title,
      dto.message,
      dto.type,
      dto.userIds,
    );
  }

  @Delete(':id')
  @ApiParam({ name: 'id' })
  @ApiOperation({ summary: 'Delete any notification' })
  @ApiResponse({ status: 200 })
  @ApiResponse({ status: 404 })
  delete(@Req() req: { user: { id: number } }, @Param('id') id: string) {
    return this.service.delete(req.user.id, +id);
  }
}
