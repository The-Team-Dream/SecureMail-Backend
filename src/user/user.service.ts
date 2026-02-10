import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma.service';

@Injectable()
export class UserService {
    constructor(
        private prisma: PrismaService
    ){}
    async profile(id: number){
        const user = await this.prisma.user.findUnique({
            where:{id: id},
            select:{
                id:true,
                username:true,
                email:true,
                avatar:true,
            }
        })
        return {user}
    } 
}
