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
import { AdminUsersService } from '../services/admin-users.service';
import { TokenGuard } from '../../auth/guards/auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from '@prisma/client';
import { AdminUsersQueryDto } from '../dto/users-query.dto';
import { AdminPaginatedDto } from '../dto/common.dto';

@ApiTags('admin/users')
@ApiStandardErrorResponses()
@Controller('admin/users')
@UseGuards(TokenGuard, RolesGuard)
@Roles(Role.ADMIN)
@ApiBearerAuth()
export class AdminUsersController {
  constructor(private readonly service: AdminUsersService) {}

  @Get()
  @ApiOperation({ summary: 'Paginated list of all users' })
  @ApiResponse({ status: 200 })
  findAll(@Query() query: AdminUsersQueryDto) {
    return this.service.findAll(
      query.page ?? 1,
      query.limit ?? 20,
      query.search,
      query.active,
      query.banned,
    );
  }

  @Get(':id')
  @ApiParam({ name: 'id' })
  @ApiOperation({ summary: 'Full user details' })
  @ApiResponse({ status: 200 })
  @ApiResponse({ status: 404 })
  findOne(@Param('id') id: string) {
    return this.service.findOne(+id);
  }

  @Patch(':id/ban')
  @ApiParam({ name: 'id' })
  @ApiOperation({ summary: 'Ban user' })
  @ApiResponse({ status: 200 })
  @ApiResponse({ status: 404 })
  ban(@Req() req: { user: { id: number } }, @Param('id') id: string) {
    return this.service.ban(req.user.id, +id);
  }

  @Patch(':id/unban')
  @ApiParam({ name: 'id' })
  @ApiOperation({ summary: 'Unban user' })
  @ApiResponse({ status: 200 })
  @ApiResponse({ status: 404 })
  unban(@Req() req: { user: { id: number } }, @Param('id') id: string) {
    return this.service.unban(req.user.id, +id);
  }

  @Delete(':id')
  @ApiParam({ name: 'id' })
  @ApiOperation({ summary: 'Soft delete user' })
  @ApiResponse({ status: 200 })
  @ApiResponse({ status: 404 })
  delete(@Req() req: { user: { id: number } }, @Param('id') id: string) {
    return this.service.softDelete(req.user.id, +id);
  }

  @Get(':id/sessions')
  @ApiParam({ name: 'id' })
  @ApiOperation({ summary: 'View user sessions' })
  @ApiResponse({ status: 200 })
  getSessions(@Param('id') id: string) {
    return this.service.getSessions(+id);
  }

  @Delete(':id/sessions')
  @ApiParam({ name: 'id' })
  @ApiOperation({ summary: 'Revoke all user sessions' })
  @ApiResponse({ status: 200 })
  revokeSessions(@Req() req: { user: { id: number } }, @Param('id') id: string) {
    return this.service.revokeAllSessions(req.user.id, +id);
  }

  @Get(':id/mailboxes')
  @ApiParam({ name: 'id' })
  @ApiOperation({ summary: 'View user mailboxes' })
  @ApiResponse({ status: 200 })
  getMailboxes(@Param('id') id: string) {
    return this.service.getMailboxes(+id);
  }

  @Get(':id/notifications')
  @ApiParam({ name: 'id' })
  @ApiOperation({ summary: 'View user notifications' })
  @ApiResponse({ status: 200 })
  getNotifications(
    @Param('id') id: string,
    @Query() query: AdminPaginatedDto,
  ) {
    return this.service.getNotifications(
      +id,
      query.page ?? 1,
      query.limit ?? 20,
    );
  }
}
