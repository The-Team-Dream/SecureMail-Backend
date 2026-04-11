import { ApiProperty } from '@nestjs/swagger';

/**
 * Standard error JSON from {@link AllExceptionsFilter} (all non-2xx HTTP API errors).
 */
export class ApiErrorResponseDto {
    @ApiProperty({ example: false, description: 'Always false for errors' })
    success!: false;

    @ApiProperty({
        example: 400,
        description: 'HTTP status code',
        enum: [400, 401, 403, 404, 409, 422, 429, 500, 503],
    })
    statusCode!: number;

    @ApiProperty({
        example: 'email must be an email',
        description: 'Primary human-readable error message',
    })
    message!: string;

    @ApiProperty({
        example: ['email must be an email', 'password must be longer than or equal to 8 characters'],
        description: 'Validation detail list (class-validator); null when a single message suffices',
        nullable: true,
        type: [String],
    })
    errors!: string[] | null;

    @ApiProperty({ example: '/auth/login', description: 'Request path' })
    path!: string;

    @ApiProperty({
        example: '2026-04-11T12:00:00.000Z',
        description: 'ISO 8601 timestamp',
    })
    timestamp!: string;
}
