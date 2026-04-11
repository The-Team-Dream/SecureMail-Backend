import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { ApiBearerAuth, ApiOperation, ApiTags } from '@nestjs/swagger';
import { UserService } from './user.service';
import { TokenGuard } from 'src/auth/guards/auth.guard';
import { ApiOkWrapped, ApiStandardErrorResponses } from 'src/common/swagger';

@ApiTags('user')
@ApiStandardErrorResponses()
@Controller('user')
@UseGuards(TokenGuard)
@ApiBearerAuth()
export class UserController {
    constructor(private userService: UserService) {}

    @Get('profile')
    @ApiOperation({ summary: 'Current user profile' })
    @ApiOkWrapped('User profile', {
        id: 1,
        email: 'user@example.com',
        username: 'john_doe',
        avatar: 'https://cdn.example/avatar.png',
        isVerified: true,
    })
    async users(@Req() req: { user: { id: number } }) {
        return this.userService.profile(req.user.id);
    }
}
