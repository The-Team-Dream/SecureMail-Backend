import { Controller, Get, Req, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { TokenGuard } from 'src/auth/guards/auth.guard';

@Controller('user')
export class UserController {
    constructor(private userService: UserService){}
    
    @UseGuards(TokenGuard)
    @Get("profile")
    async users(@Req() req) {        
        return this.userService.profile(req.user.id)
    }
}
