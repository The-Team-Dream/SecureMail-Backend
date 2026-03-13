// src/security/pipeline/url-sandbox/url-sandbox.module.ts
import { Module } from '@nestjs/common';
import { UrlSandboxService } from './url-sandbox.service';

@Module({
    providers: [UrlSandboxService],
    exports: [UrlSandboxService],
})
export class UrlSandboxModule { }