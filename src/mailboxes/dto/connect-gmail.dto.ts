import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsNotEmpty, IsString, IsOptional } from 'class-validator';

export class ConnectGmailDto {
  @ApiProperty({
    description: 'OAuth2 authorization code from Gmail callback',
    example: '4/0AY0e-g7...',
  })
  @IsString()
  @IsNotEmpty()
  code: string;

  @ApiProperty({
    description: 'Redirect URI used in the OAuth flow (must match Google Console)',
    example: 'http://localhost:3000/mailboxes/gmail/callback',
  })
  @IsString()
  // @IsUrl()
  redirectUri: string;

  @ApiPropertyOptional({
    description: 'Optional custom display name for the mailbox',
  })
  @IsString()
  @IsOptional()
  displayName?: string;
}
