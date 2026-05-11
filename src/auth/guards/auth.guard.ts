import { CanActivate, ExecutionContext, ForbiddenException, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Request } from 'express';
import { PrismaService } from 'src/prisma.service';
import { AuthService } from '../auth.service';
import { Reflector } from '@nestjs/core';
import { IS_PUBLIC_KEY } from '../decorators/public.decorator';

@Injectable()
export class TokenGuard implements CanActivate {

  constructor(
    private jwtService: JwtService,
    private prisma: PrismaService,
    private authService: AuthService,
    private reflector: Reflector,
  ) { }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers.authorization?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);
    if (isPublic) {
      return true;
    }

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
          role: true,
          bannedAt: true,
          deletedAt: true,
        }
      });
      if (!user) {
        throw new UnauthorizedException();
      }
      if (user.deletedAt) {
        throw new UnauthorizedException('Account has been deleted');
      }
      if (user.bannedAt) {
        throw new ForbiddenException('Account has been banned');
      }
      if (!user.isVerified) {
        throw new ForbiddenException('Account not verified');
      }
      request['user'] = user
      if (payload.sessionId) {
        request['sessionId'] = payload.sessionId
      }
    } catch (error) {
      if (error instanceof ForbiddenException || error instanceof UnauthorizedException) {
        throw error;
      }
      console.error('TokenGuard verification failed:', error);
      throw new UnauthorizedException('Invalid or expired token');
    }
    return true;
  }
}
