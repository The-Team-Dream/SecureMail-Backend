import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { AuthGuard } from 'src/auth/auth.guard';

@Controller('user')
export class UserController {
    constructor(private userService: UserService){}
    
    @UseGuards(AuthGuard)
    @Get("profile")
    async users(@Req() req) {
        return this.userService.profile(req.user.userId)
    }
}
 //887640