import { ApiProperty } from '@nestjs/swagger';

/**
 * Every successful JSON response is wrapped by {@link ResponseInterceptor}.
 * The `data` field shape is documented per-endpoint (DTO or schema example).
 */
export class ApiSuccessEnvelopeDto {
    @ApiProperty({ example: true })
    success!: true;

    @ApiProperty({ example: 'Request successful' })
    message!: string;

    @ApiProperty({
        description: 'Endpoint-specific payload',
        type: 'object',
        additionalProperties: true,
        example: { id: 1, email: 'user@example.com' },
    })
    data!: unknown;
}
