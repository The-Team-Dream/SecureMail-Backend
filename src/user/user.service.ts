import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma.service';

@Injectable()
export class UserService {
    constructor(
        private prisma: PrismaService
    ){}
    async profile(id: number){
        const user = await this.prisma.user.findUnique({
            where:{id: id}
        })
        return {user}
    } 
}
//122318