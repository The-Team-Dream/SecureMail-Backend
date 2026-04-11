import {
  Controller,
  Get,
  Param,
  Query,
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
import { AdminEmailsService } from '../services/admin-emails.service';
import { TokenGuard } from '../../auth/guards/auth.guard';
import { RolesGuard } from '../../auth/guards/roles.guard';
import { Roles } from '../../common/decorators/roles.decorator';
import { Role } from 'generated/prisma/enums';
import { AdminEmailsQueryDto } from '../dto/emails-query.dto';
import { AdminPaginatedDto } from '../dto/common.dto';

@ApiTags('admin/emails')
@ApiStandardErrorResponses()
@Controller('admin/emails')
@UseGuards(TokenGuard, RolesGuard)
@Roles(Role.ADMIN)
@ApiBearerAuth()
export class AdminEmailsController {
  constructor(private readonly service: AdminEmailsService) {}

  @Get('phishing')
  @ApiOperation({ summary: 'Paginated list of phishing emails' })
  @ApiResponse({ status: 200 })
  getPhishing(@Query() query: AdminPaginatedDto) {
    return this.service.getPhishing(query.page ?? 1, query.limit ?? 20);
  }

  @Get('spam')
  @ApiOperation({ summary: 'Paginated list of spam emails' })
  @ApiResponse({ status: 200 })
  getSpam(@Query() query: AdminPaginatedDto) {
    return this.service.getSpam(query.page ?? 1, query.limit ?? 20);
  }

  @Get()
  @ApiOperation({ summary: 'Paginated list of all emails with filters' })
  @ApiResponse({ status: 200 })
  findAll(@Query() query: AdminEmailsQueryDto) {
    return this.service.findAll(
      query.page ?? 1,
      query.limit ?? 20,
      {
        classification: query.classification,
        fromDate: query.fromDate,
        toDate: query.toDate,
        mailboxId: query.mailboxId,
        search: query.search,
      },
    );
  }

  @Get(':id')
  @ApiParam({ name: 'id' })
  @ApiOperation({ summary: 'Full email details' })
  @ApiResponse({ status: 200 })
  @ApiResponse({ status: 404 })
  findOne(@Param('id') id: string) {
    return this.service.findOne(+id);
  }
}
