import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsNotEmpty, IsString, IsUrl, IsOptional } from 'class-validator';

export class ConnectOutlookDto {
  @ApiProperty({
    description: 'OAuth2 authorization code from Microsoft callback',
    example: 'M.R3_BAY...',
  })
  @IsString()
  @IsNotEmpty()
  code: string;

  @ApiProperty({
    description: 'Redirect URI used in the OAuth flow (must match Azure App registration)',
    example: 'http://localhost:3001/mailboxes/outlook/callback',
  })
  @IsString()
  @IsUrl()
  redirectUri: string;

  @ApiPropertyOptional({
    description: 'Optional custom display name for the mailbox',
  })
  @IsString()
  @IsOptional()
  displayName?: string;
}
