import {
  Controller,
  Get,
  Patch,
  Delete,
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
import { NotificationsService } from './notifications.service';
import { TokenGuard } from '../auth/guards/auth.guard';
import { PaginatedNotificationsDto } from './dto/paginated-notifications.dto';
function ApiParamIdDecorator() {
  return ApiParam({ name: 'id', description: 'Notification ID', type: Number });
}

@ApiTags('notifications')
@ApiStandardErrorResponses()
@Controller('notifications')
@UseGuards(TokenGuard)
@ApiBearerAuth()
export class NotificationsController {
  constructor(private readonly notificationsService: NotificationsService) {}

  @Get()
  @ApiOperation({ summary: 'Get paginated list of notifications' })
  @ApiResponse({ status: 200, description: 'Paginated notifications list' })
  findAll(
    @Req() req: { user: { id: number } },
    @Query() query: PaginatedNotificationsDto,
  ) {
    return this.notificationsService.findAll(
      req.user.id,
      query.page ?? 1,
      query.limit ?? 20,
    );
  }

  @Get('unread-count')
  @ApiOperation({ summary: 'Get count of unread notifications' })
  @ApiResponse({ status: 200, description: 'Unread count' })
  getUnreadCount(@Req() req: { user: { id: number } }) {
    return this.notificationsService.getUnreadCount(req.user.id);
  }

  @Patch('read-all')
  @ApiOperation({ summary: 'Mark all notifications as read' })
  @ApiResponse({ status: 200, description: 'All notifications marked as read' })
  markAllAsRead(@Req() req: { user: { id: number } }) {
    return this.notificationsService.markAllAsRead(req.user.id);
  }

  @Patch(':id/read')
  @ApiParamIdDecorator()
  @ApiOperation({ summary: 'Mark notification as read' })
  @ApiResponse({ status: 200, description: 'Notification marked as read' })
  @ApiResponse({ status: 404, description: 'Notification not found' })
  markAsRead(@Req() req: { user: { id: number } }, @Param('id') id: string) {
    return this.notificationsService.markAsRead(req.user.id, +id);
  }

  @Delete(':id')
  @ApiParamIdDecorator()
  @ApiOperation({ summary: 'Delete notification' })
  @ApiResponse({ status: 200, description: 'Notification deleted' })
  @ApiResponse({ status: 404, description: 'Notification not found' })
  delete(@Req() req: { user: { id: number } }, @Param('id') id: string) {
    return this.notificationsService.delete(req.user.id, +id);
  }
}
