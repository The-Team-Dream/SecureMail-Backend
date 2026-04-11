import {
  BadRequestException,
  Controller,
  Delete,
  Get,
  Param,
  ParseIntPipe,
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
import { SessionResponseDto } from './dto/session-response.dto';
import { SessionsService } from './sessions.service';
import { TokenGuard } from 'src/auth/guards/auth.guard';

interface RequestWithUser {
  user: { id: number };
  sessionId?: number;
}

@ApiTags('sessions')
@ApiStandardErrorResponses()
@ApiBearerAuth()
@Controller('sessions')
@UseGuards(TokenGuard)
export class SessionsController {
  constructor(private readonly sessionsService: SessionsService) {}

  @Get()
  @ApiOperation({ summary: 'List all active sessions for current user' })
  @ApiResponse({ status: 200, description: 'List of active sessions', type: [SessionResponseDto] })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getSessions(@Req() req: RequestWithUser) {
    return this.sessionsService.getSessionsForUser(
      req.user.id,
      req.sessionId,
    );
  }

  @Delete()
  @ApiOperation({ summary: 'Revoke all sessions except current' })
  @ApiResponse({ status: 200, description: 'All other sessions revoked' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async revokeAllSessions(@Req() req: RequestWithUser) {
    if (!req.sessionId) {
      throw new BadRequestException('Session ID required for this operation');
    }
    const result = await this.sessionsService.revokeAllSessionsExcept(
      req.user.id,
      req.sessionId,
    );
    return {
      message: `${result.revokedCount} session(s) revoked successfully`,
      revokedCount: result.revokedCount,
    };
  }

  @Delete(':id')
  @ApiOperation({ summary: 'Revoke a specific session' })
  @ApiParam({ name: 'id', description: 'Session ID to revoke' })
  @ApiResponse({ status: 200, description: 'Session revoked successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 403, description: 'Forbidden - cannot revoke others sessions' })
  @ApiResponse({ status: 404, description: 'Session not found' })
  async revokeSession(
    @Param('id', ParseIntPipe) id: number,
    @Req() req: RequestWithUser,
  ) {
    await this.sessionsService.revokeSession(id, req.user.id);
    return { message: 'Session revoked successfully' };
  }
}
