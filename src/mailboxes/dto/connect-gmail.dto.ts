import { ApiProperty } from '@nestjs/swagger';
import { IsNotEmpty, IsString, IsUrl } from 'class-validator';

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
    example: 'http://localhost:3001/mailboxes/gmail/callback',
  })
  @IsString()
  @IsUrl()
  redirectUri: string;
}
