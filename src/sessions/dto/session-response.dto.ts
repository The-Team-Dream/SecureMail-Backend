import { ApiProperty } from '@nestjs/swagger';

export class SessionResponseDto {
  @ApiProperty({ description: 'Session ID', example: 1 })
  id: number;

  @ApiProperty({ description: 'IP address at login', example: '192.168.1.1' })
  ipAddress: string;

  @ApiProperty({ description: 'Operating system', example: 'Windows', nullable: true })
  deviceOs: string | null;

  @ApiProperty({ description: 'Browser name', example: 'Chrome', nullable: true })
  deviceBrowser: string | null;

  @ApiProperty({ description: 'Raw user agent string' })
  userAgent: string;

  @ApiProperty({ description: 'Login timestamp' })
  loginAt: Date;

  @ApiProperty({ description: 'Session expiration timestamp' })
  expiresAt: Date;

  @ApiProperty({ description: 'Whether this is the current session', example: false })
  isCurrent?: boolean;
}
