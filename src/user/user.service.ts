import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma.service';

@Injectable()
export class UserService {
    constructor(
        private prisma: PrismaService
    ){}
    async users(){
        const users = await this.prisma.user.findMany()
        return {users}
    } 
}
