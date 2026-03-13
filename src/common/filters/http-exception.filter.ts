// ─────────────────────────────────────────────────────────────────────────────
// common/filters/http-exception.filter.ts
//
// UPDATED: Proper contextual error messages
//
// Problems with the old filter:
//   1. Prisma errors (P2025 record not found, P2002 unique constraint) were
//      swallowed as generic "Internal server error" — no useful info to client
//   2. Validation errors from class-validator came as arrays but weren't
//      formatted consistently
//   3. No request context (method + path) in the error response — harder
//      to debug from frontend logs
//   4. JWT errors from @nestjs/jwt came as raw strings, not clean messages
//
// What's fixed:
//   - Prisma P2025 → "Record not found" (404)
//   - Prisma P2002 → "This [field] is already in use" (409)
//   - Prisma P2003 → "Related record not found" (400)
//   - class-validator arrays → joined as readable string
//   - JWT errors → clean "Invalid or expired token" (401)
//   - All errors include: success, statusCode, message, errors[], path, timestamp
// ─────────────────────────────────────────────────────────────────────────────

import {
  ExceptionFilter,
  Catch,
  ArgumentsHost,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Request, Response } from 'express';

// ── Prisma error shape (minimal — only what we need) ─────────────────────────
interface PrismaClientKnownError {
  code:    string;
  meta?:   { target?: string[]; cause?: string };
  message: string;
}

function isPrismaError(err: unknown): err is PrismaClientKnownError {
  if (typeof err !== 'object' || err === null) {
    return false;
  }

  const maybeErr = err as Record<string, unknown>;

  return (
    'code' in maybeErr &&
    typeof maybeErr.code === 'string' &&
    maybeErr.code.startsWith('P')
  );
}

@Catch()
export class AllExceptionsFilter implements ExceptionFilter {
  private readonly logger = new Logger(AllExceptionsFilter.name);

  catch(exception: unknown, host: ArgumentsHost): void {
    const ctx      = host.switchToHttp();
    const response = ctx.getResponse<Response>();
    const request  = ctx.getRequest<Request>();

    const { status, message, errors } = this.resolveError(exception);

    // Log 5xx errors for monitoring — 4xx are expected client errors
    if (status >= 500) {
      this.logger.error(
        `[${request.method}] ${request.url} → ${status}`,
        exception instanceof Error ? exception.stack : String(exception),
      );
    }

    response.status(status).json({
      success:    false,
      statusCode: status,
      message,
      errors:     errors ?? null,
      path:       request.url,
      timestamp:  new Date().toISOString(),
    });
  }

  private resolveError(exception: unknown): {
    status:  number;
    message: string;
    errors?: string[];
  } {

    // ── 1. NestJS HttpException (BadRequestException, NotFoundException, etc.) ──
    if (exception instanceof HttpException) {
      const status = exception.getStatus();
      const res    = exception.getResponse();

      // class-validator returns { message: string[] } for validation errors
      if (typeof res === 'object' && res !== null) {
        const obj = res as { message?: string | string[]; error?: string };

        if (Array.isArray(obj.message)) {
          // Format validation error array into a readable single message
          const errors = obj.message as string[];
          return {
            status,
            message: this.formatValidationErrors(errors),
            errors,
          };
        }

        return {
          status,
          message: obj.message ?? exception.message,
        };
      }

      return { status, message: String(res) };
    }

    // ── 2. Prisma known errors ────────────────────────────────────────────────
    if (isPrismaError(exception)) {
      return this.resolvePrismaError(exception);
    }

    // ── 3. JWT / token errors ─────────────────────────────────────────────────
    if (exception instanceof Error) {
      if (
        exception.name === 'JsonWebTokenError' ||
        exception.name === 'TokenExpiredError' ||
        exception.name === 'NotBeforeError'
      ) {
        return {
          status:  HttpStatus.UNAUTHORIZED,
          message: 'Invalid or expired authentication token. Please log in again.',
        };
      }

      // Multer file size error
      if (exception.message?.includes('File too large')) {
        return {
          status:  HttpStatus.BAD_REQUEST,
          message: 'One or more attachments exceed the 10MB file size limit. Please reduce file sizes and try again.',
        };
      }

      // Multer file count error
      if (exception.message?.includes('Too many files')) {
        return {
          status:  HttpStatus.BAD_REQUEST,
          message: 'Too many attachments. A maximum of 10 files are allowed per email.',
        };
      }
    }

    // ── 4. Unknown / unhandled errors ─────────────────────────────────────────
    return {
      status:  HttpStatus.INTERNAL_SERVER_ERROR,
      message: 'An unexpected error occurred. Please try again later.',
    };
  }

  private resolvePrismaError(err: PrismaClientKnownError): {
    status:  number;
    message: string;
  } {
    switch (err.code) {

      // Record not found (e.g. update/delete on non-existent ID)
      case 'P2025':
        return {
          status:  HttpStatus.NOT_FOUND,
          message: 'The requested record was not found.',
        };

      // Unique constraint violation (e.g. duplicate email on register)
      case 'P2002': {
        const fields = err.meta?.target?.join(', ') ?? 'field';
        return {
          status:  HttpStatus.CONFLICT,
          message: `A record with this ${fields} already exists.`,
        };
      }

      // Foreign key constraint (e.g. referencing a mailbox that doesn't exist)
      case 'P2003':
        return {
          status:  HttpStatus.BAD_REQUEST,
          message: 'Related record not found. Please check the provided IDs.',
        };

      // Required field missing
      case 'P2011':
        return {
          status:  HttpStatus.BAD_REQUEST,
          message: 'A required field is missing in the request.',
        };

      // Value too long for column
      case 'P2000':
        return {
          status:  HttpStatus.BAD_REQUEST,
          message: 'One or more values exceed the maximum allowed length.',
        };

      // Database connection issue
      case 'P1001':
      case 'P1002':
        return {
          status:  HttpStatus.SERVICE_UNAVAILABLE,
          message: 'Database is temporarily unavailable. Please try again shortly.',
        };

      default:
        this.logger.error(`Unhandled Prisma error code: ${err.code}`, err.message);
        return {
          status:  HttpStatus.INTERNAL_SERVER_ERROR,
          message: 'A database error occurred. Please try again later.',
        };
    }
  }

  // ── Format class-validator array into a single human-readable string ─────────
  // Input:  ['email must be an email', 'password must be longer than 8 characters']
  // Output: 'email must be an email; password must be longer than 8 characters'
  private formatValidationErrors(errors: string[]): string {
    if (errors.length === 1) return errors[0];
    return errors.join('; ');
  }
}
