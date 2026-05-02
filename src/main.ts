import { NestFactory } from '@nestjs/core';
import { ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';
import { ApiErrorResponseDto } from './common/swagger/api-error-response.dto';
import { ApiSuccessEnvelopeDto } from './common/swagger/api-success-envelope.dto';
import { IoAdapter } from '@nestjs/platform-socket.io';
import { AppModule } from './app.module';
import { ResponseInterceptor } from './common/interceptors/response.interceptor';
import { AllExceptionsFilter } from './common/filters/http-exception.filter';
import {
  contentSecurityPolicy,
  hsts,
  frameguard,
  noSniff,
  referrerPolicy,
  crossOriginOpenerPolicy,
  crossOriginEmbedderPolicy,
} from 'helmet';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);

  const isDev = process.env.NODE_ENV !== 'production';

  // Security headers via helmet (CSP skipped in dev to allow Swagger)
  app.use(frameguard({ action: 'deny' }));
  app.use(noSniff());

  if (!isDev) {
    app.use(hsts({ maxAge: 31536000, includeSubDomains: true, preload: true }));
  }
  app.use(referrerPolicy({ policy: 'strict-origin-when-cross-origin' }));

  if (!isDev) {
    app.use(crossOriginOpenerPolicy({ policy: 'same-origin' }));
    app.use(crossOriginEmbedderPolicy({ policy: 'require-corp' }));
  }

  // CSP enabled in production only
  if (!isDev) {
    app.use(
      contentSecurityPolicy({
        directives: {
          defaultSrc: ["'none'"],
          scriptSrc: ["'self'"],
          styleSrc: ["'self'", "'unsafe-inline'"],
          imgSrc: ["'self'", 'data:'],
          connectSrc: ["'self'", 'ws:', 'wss:'],
          fontSrc: ["'self'"],
          objectSrc: ["'none'"],
          frameSrc: ["'none'"],
          upgradeInsecureRequests: [],
        },
      }),
    );
  }

  app.useWebSocketAdapter(new IoAdapter(app));

  app.enableCors({
    origin: process.env.FRONTEND_URL ?? 'http://localhost:3001',
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
  });

  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );
  app.useGlobalInterceptors(new ResponseInterceptor());
  app.useGlobalFilters(new AllExceptionsFilter());

  const config = new DocumentBuilder()
    .setTitle('SecureMail API')
    .setDescription(
      [
        'Production REST API for SecureMail (NestJS).',
        '',
        '**Response shape:** Successful JSON responses are wrapped as `{ success: true, message: string, data: T }` (global interceptor).',
        'Errors use `{ success: false, statusCode, message, errors, path, timestamp }`.',
        '',
        '**Auth:** Send `Authorization: Bearer <access_token>` unless the operation is marked public.',
        '',
        '**OpenAPI JSON:** `GET /api/docs-json` (for codegen in Flutter / TypeScript clients).',
      ].join('\n'),
    )
    .setVersion('1.0.0')
    .setContact('SecureMail', 'https://github.com/securemail', 'api@securemail.local')
    .addBearerAuth({
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'JWT',
      description: 'JWT access token from POST /auth/login or POST /auth/verify-2fa',
    })
    .addServer(process.env.PUBLIC_API_URL ?? 'http://localhost:3000', 'Current')
    .build();

  const document = SwaggerModule.createDocument(app, config, {
    extraModels: [ApiErrorResponseDto, ApiSuccessEnvelopeDto],
    operationIdFactory: (controllerKey: string, methodKey: string) =>
      `${controllerKey.replace(/Controller$/, '')}_${methodKey}`,
  });

  SwaggerModule.setup('api/docs', app, document, {
    swaggerOptions: {
      persistAuthorization: true,
      docExpansion: 'list',
      filter: true,
      showRequestDuration: true,
    },
    customSiteTitle: 'SecureMail API Docs',
  });

  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
