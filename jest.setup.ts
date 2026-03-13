// jest.setup.ts
import { Logger } from '@nestjs/common';

// Suppress NestJS logger during tests — warnings/logs are expected behavior
// not errors, and they clutter the test output
beforeAll(() => {
    jest.spyOn(Logger.prototype, 'warn').mockImplementation(() => { });
    jest.spyOn(Logger.prototype, 'log').mockImplementation(() => { });
    jest.spyOn(Logger.prototype, 'error').mockImplementation(() => { });
});

afterAll(() => {
    jest.restoreAllMocks();
});