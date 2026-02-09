import { Controller, Get, UseGuards } from '@nestjs/common';
import { UserService } from './user.service';
import { AuthGuard } from 'src/auth/auth.guard';

@Controller('user')
export class UserController {
    constructor(private userService: UserService){}
    
    @UseGuards(AuthGuard)
    @Get("all")
    async users() {
        return this.userService.users()
    }
}
 