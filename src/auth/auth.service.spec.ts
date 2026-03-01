import { Test, TestingModule } from '@nestjs/testing';
import { JwtService } from '@nestjs/jwt';
import { BadRequestException, UnauthorizedException } from '@nestjs/common';
import { PrismaService } from '../prisma.service';
import { NodeMailerService } from '../node-mailer/node-mailer.service';
import { getRedisConnectionToken } from '@nestjs-modules/ioredis';
import { RegisterDto } from './dto/register.dto';
import { AuthService } from './auth.service';

jest.mock('src/prisma.service', () => ({
  PrismaService: jest.fn().mockImplementation(() => ({
    user: {
      findUnique: jest.fn(),
      findFirst: jest.fn(),
      create: jest.fn(),
      update: jest.fn(),
    },
  })),
}));
jest.mock('bcrypt', () => ({
  hash: jest.fn().mockResolvedValue('$2b$10$hashed'),
  compare: jest.fn().mockResolvedValue(true),
}));

describe('AuthService', () => {
  let service: AuthService;
  let prisma: PrismaService;
  let jwtService: JwtService;
  let mailerService: NodeMailerService;
  let redis: { set: jest.Mock; get: jest.Mock };

  const mockUser = {
    id: 1,
    email: 'test@example.com',
    provider: 'local',
    username: 'testuser',
    passwordHash: '$2b$10$hashed',
    isVerified: true,
  };

  beforeEach(async () => {
    redis = { set: jest.fn(), get: jest.fn().mockResolvedValue(null) };
    const module: TestingModule = await Test.createTestingModule({
      providers: [
        AuthService,
        {
          provide: PrismaService,
          useValue: {
            user: {
              findUnique: jest.fn(),
              findFirst: jest.fn(),
              create: jest.fn(),
              update: jest.fn(),
            },
          },
        },
        {
          provide: JwtService,
          useValue: { signAsync: jest.fn().mockResolvedValue('jwt-token'), decode: jest.fn(), verifyAsync: jest.fn() },
        },
        {
          provide: NodeMailerService,
          useValue: { sendOTP: jest.fn(), welcome: jest.fn(), resetPassword: jest.fn() },
        },
        { provide: getRedisConnectionToken(), useValue: redis },
      ],
    }).compile();

    service = module.get<AuthService>(AuthService);
    prisma = module.get<PrismaService>(PrismaService);
    jwtService = module.get<JwtService>(JwtService);
    mailerService = module.get<NodeMailerService>(NodeMailerService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });

  describe('register', () => {
    it('should throw BadRequestException if email exists', async () => {
      jest.spyOn(prisma.user, 'findUnique').mockResolvedValue(mockUser as any);
      const dto: RegisterDto = {
        email: 'test@example.com',
        password: 'Password1',
        confirmPassword: 'Password1',
        username: 'testuser',
      };
      await expect(service.register(dto)).rejects.toThrow(BadRequestException);
    });

    it('should create user and send OTP when email is unique', async () => {
      jest.spyOn(prisma.user, 'findUnique').mockResolvedValue(null);
      jest.spyOn(prisma.user, 'create').mockResolvedValue(mockUser as any);
      const dto: RegisterDto = {
        email: 'new@example.com',
        password: 'Password1',
        confirmPassword: 'Password1',
        username: 'newuser',
      };
      const result = await service.register(dto);
      expect(result).toEqual({ message: 'OTP sent to your email' });
      expect(prisma.user.create).toHaveBeenCalled();
      expect(mailerService.sendOTP).toHaveBeenCalled();
    });
  });

  describe('login', () => {
    it('should throw UnauthorizedException for invalid credentials', async () => {
      jest.spyOn(prisma.user, 'findUnique').mockResolvedValue(null);
      await expect(
        service.login({ email: 'bad@example.com', password: 'wrong' }),
      ).rejects.toThrow(UnauthorizedException);
    });

    it('should return token for valid credentials', async () => {
      jest.spyOn(prisma.user, 'findUnique').mockResolvedValue(mockUser as any);
      const result = await service.login({
        email: 'test@example.com',
        password: 'Password1',
      });
      expect(result).toEqual({ token: 'jwt-token' });
    });
  });

  describe('logout', () => {
    it('should blacklist token', async () => {
      (jwtService.decode as jest.Mock).mockReturnValue({ exp: Math.floor(Date.now() / 1000) + 60 });
      const result = await service.logout('some-token');
      expect(result).toEqual({ message: 'Logout successfully' });
      expect(redis.set).toHaveBeenCalledWith('bl:some-token', 'blacklisted', 'EX', expect.any(Number));
    });
  });
});
