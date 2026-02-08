import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from 'src/prisma.service';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwtService: JwtService,
    ) { }

    async register(data: { email: string; password: string; name: string }) {
        const existingUser = await this.prisma.user.findUnique({
            where: { email: data.email }
        })
        if (existingUser) {
            throw new BadRequestException('Email already in use')
        }
        const hashedPassword = await bcrypt.hash(data.password, 10)
        const user = await this.prisma.user.create({
            data:{
                email: data.email,
                password: hashedPassword,
                name: data.name
            }
        })
        const token = this.jwtService.sign({userId: user.id})
        return {user, token}
    }

    async login(data:{email: string; password: string}){
        const user = await this.prisma.user.findUnique({where:{email: data.email}})
        if(!user){
            throw new UnauthorizedException("Invalid credentials")
        }
        const passwordValid = await bcrypt.compare(data.password, user.password)
        if(!passwordValid){
            throw new UnauthorizedException("Invalid credentials")
        }
        const token = this.jwtService.sign({userId:user.id})
        return {user, token}
    }
}
