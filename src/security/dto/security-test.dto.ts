import { ApiProperty, ApiPropertyOptional } from '@nestjs/swagger';
import { IsArray, IsNumber, IsObject, IsOptional, IsString } from 'class-validator';

export class AnalyzeEmailDto {
    @ApiPropertyOptional({ example: 'sender@example.com' })
    @IsOptional()
    @IsString()
    fromAddr?: string;

    @ApiPropertyOptional({ example: 'Sender Name' })
    @IsOptional()
    @IsString()
    fromName?: string;

    @ApiPropertyOptional({ example: 'recipient@company.com' })
    @IsOptional()
    @IsString()
    toAddr?: string;

    @ApiPropertyOptional({ example: 'Invoice due' })
    @IsOptional()
    @IsString()
    subject?: string;

    @ApiPropertyOptional({ example: 'Plain text body' })
    @IsOptional()
    @IsString()
    bodyText?: string;

    @ApiPropertyOptional({ example: '<p>HTML body</p>' })
    @IsOptional()
    @IsString()
    bodyHtml?: string;

    @ApiPropertyOptional({
        example: { 'authentication-results': 'spf=pass' },
        type: 'object',
        additionalProperties: { type: 'string' },
    })
    @IsOptional()
    @IsObject()
    headers?: Record<string, string>;

    @ApiPropertyOptional({ example: 1 })
    @IsOptional()
    @IsNumber()
    mailBoxId?: number;

    @ApiPropertyOptional({ example: 1, description: 'User id for pipeline context' })
    @IsOptional()
    @IsNumber()
    userId?: number;

    @ApiPropertyOptional({
        type: 'array',
        items: {
            type: 'object',
            properties: {
                filename: { type: 'string' },
                mimeType: { type: 'string' },
                size: { type: 'number' },
                storagePath: { type: 'string' },
            },
        },
    })
    @IsOptional()
    @IsArray()
    attachments?: Array<{
        filename: string;
        mimeType: string;
        size: number;
        storagePath: string;
    }>;
}

export class IntelUrlDto {
    @ApiProperty({ example: 'https://example.com/path' })
    @IsString()
    url!: string;
}

export class IntelIpDto {
    @ApiProperty({ example: '8.8.8.8' })
    @IsString()
    ip!: string;
}

export class IntelDomainDto {
    @ApiProperty({ example: 'example.com' })
    @IsString()
    domain!: string;
}

export class CacheInvalidateDto {
    @ApiProperty({ enum: ['url', 'ip', 'domain'], example: 'url' })
    @IsString()
    type!: 'url' | 'ip' | 'domain';

    @ApiProperty({ example: 'https://evil.test/phish' })
    @IsString()
    value!: string;
}
