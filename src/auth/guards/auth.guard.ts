import { CanActivate, ExecutionContext, ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { PrismaService } from 'src/prisma.service';
import { AuthService } from '../auth.service';

@Injectable()
export class TokenGuard implements CanActivate {

  constructor(
    private jwtService: JwtService,
    private prisma: PrismaService,
    private authService: AuthService,
  ) { }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const request = context.switchToHttp().getRequest()
    const token = this.extractTokenFromHeader(request)
    if (!token) {
      throw new UnauthorizedException()
    }
    const isBlacklisted =
      await this.authService.isBlacklisted(token);

    if (isBlacklisted) {
      throw new UnauthorizedException();
    }

    try {
      const payload = await this.jwtService.verifyAsync(token)
      const user = await this.prisma.user.findUnique({
        where: { id: payload.userId },
        select: {
          id: true,
          isVerified: true, 
        }
      });
      if (!user) {
        throw new UnauthorizedException();
      }
      if (!user?.isVerified) {
        throw new ForbiddenException('Account not verified');
      }
      request['user'] = user
    } catch {
      throw new UnauthorizedException()
    }
    return true;
  }
}
