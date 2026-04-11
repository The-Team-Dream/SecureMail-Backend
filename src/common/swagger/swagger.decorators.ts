import { applyDecorators } from '@nestjs/common';
import {
    ApiBadRequestResponse,
    ApiConflictResponse,
    ApiExtraModels,
    ApiForbiddenResponse,
    ApiInternalServerErrorResponse,
    ApiNotFoundResponse,
    ApiOkResponse,
    ApiServiceUnavailableResponse,
    ApiTooManyRequestsResponse,
    ApiUnauthorizedResponse,
} from '@nestjs/swagger';
import { ApiErrorResponseDto } from './api-error-response.dto';

const err = (): typeof ApiErrorResponseDto => ApiErrorResponseDto;

/**
 * Standard client and server errors for authenticated REST endpoints.
 */
export function ApiStandardErrorResponses() {
    return applyDecorators(
        ApiBadRequestResponse({
            description: 'Validation failed, malformed body/query, or business rule rejection',
            type: err(),
        }),
        ApiUnauthorizedResponse({
            description: 'Missing or invalid Bearer JWT',
            type: err(),
        }),
        ApiForbiddenResponse({
            description: 'Authenticated but not allowed for this resource',
            type: err(),
        }),
        ApiNotFoundResponse({
            description: 'Resource not found',
            type: err(),
        }),
        ApiConflictResponse({
            description: 'Conflict (e.g. duplicate unique field)',
            type: err(),
        }),
        ApiTooManyRequestsResponse({
            description: 'Rate limit exceeded',
            type: err(),
        }),
        ApiInternalServerErrorResponse({
            description: 'Unexpected server error',
            type: err(),
        }),
        ApiServiceUnavailableResponse({
            description: 'Dependency unavailable (e.g. database)',
            type: err(),
        }),
    );
}

/**
 * For public routes (login, register): no 401 as “missing token” for the route itself.
 */
export function ApiPublicErrorResponses() {
    return applyDecorators(
        ApiBadRequestResponse({ description: 'Validation or bad input', type: err() }),
        ApiConflictResponse({ description: 'Conflict', type: err() }),
        ApiInternalServerErrorResponse({ description: 'Unexpected server error', type: err() }),
        ApiServiceUnavailableResponse({ description: 'Service unavailable', type: err() }),
    );
}

/**
 * OpenAPI schema for {@link ResponseInterceptor} success wrapper with an example `data` object.
 */
export function ApiOkWrapped(description: string, dataExample: Record<string, unknown>) {
    return ApiOkResponse({
        description,
        schema: {
            type: 'object',
            required: ['success', 'message', 'data'],
            properties: {
                success: { type: 'boolean', example: true },
                message: { type: 'string', example: 'Request successful' },
                data: {
                    type: 'object',
                    example: dataExample,
                    additionalProperties: true,
                },
            },
        },
    });
}

export function ApiExtraErrorModel() {
    return ApiExtraModels(ApiErrorResponseDto);
}
