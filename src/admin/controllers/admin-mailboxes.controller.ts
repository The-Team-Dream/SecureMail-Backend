import {
  Controller,
  Get,
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
import { AdminMailboxesService } from '../services/admin-mailboxes.service';
import { TokenGuard } from '../../auth/guards/auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from 'generated/prisma/enums';
import { AdminPaginatedDto } from '../dto/common.dto';

@ApiTags('admin/mailboxes')
@Controller('admin/mailboxes')
@UseGuards(TokenGuard, RolesGuard)
@Roles(Role.ADMIN)
@ApiBearerAuth()
export class AdminMailboxesController {
  constructor(private readonly service: AdminMailboxesService) {}

  @Get()
  @ApiOperation({ summary: 'Paginated list of all mailboxes' })
  @ApiResponse({ status: 200 })
  findAll(@Query() query: AdminPaginatedDto) {
    return this.service.findAll(query.page ?? 1, query.limit ?? 20);
  }

  @Get(':id')
  @ApiParam({ name: 'id' })
  @ApiOperation({ summary: 'Mailbox details with stats' })
  @ApiResponse({ status: 200 })
  @ApiResponse({ status: 404 })
  findOne(@Param('id') id: string) {
    return this.service.findOne(+id);
  }

  @Delete(':id')
  @ApiParam({ name: 'id' })
  @ApiOperation({ summary: 'Force disconnect mailbox' })
  @ApiResponse({ status: 200 })
  @ApiResponse({ status: 404 })
  disconnect(@Req() req: { user: { id: number } }, @Param('id') id: string) {
    return this.service.forceDisconnect(req.user.id, +id);
  }
}
