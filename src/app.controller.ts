import { Controller, Get } from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { AppService } from './app.service';
import { ApiStandardErrorResponses } from './common/swagger';

@ApiTags('health')
@ApiStandardErrorResponses()
@Controller()
export class AppController {
    constructor(private readonly appService: AppService) {}

    @Get()
    @ApiOperation({ summary: 'API root / liveness' })
    @ApiOkResponse({
        description: 'Plain text greeting wrapped by global interceptor',
        schema: {
            example: {
                success: true,
                message: 'Request successful',
                data: 'SecureMail API',
            },
        },
    })
    getHello(): string {
        return this.appService.getHello();
    }
}
