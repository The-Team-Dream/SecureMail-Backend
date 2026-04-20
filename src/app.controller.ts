import { Controller, Get } from '@nestjs/common';
import { ApiOkResponse, ApiOperation, ApiTags } from '@nestjs/swagger';
import { AppService } from './app.service';
import { ApiStandardErrorResponses } from './common/swagger';

@ApiTags('health')
@ApiStandardErrorResponses()
@Controller()
export class AppController {
    constructor(private readonly appService: AppService) {}

    @Get('health')
    @ApiOperation({ summary: 'API /health liveness with full health check' })
    @ApiOkResponse({
        description: 'Health status of all connected services',
        schema: {
            example: {
                success: true,
                message: 'Health check completed',
                data: {
                    overall: 'healthy',
                    database: 'healthy',
                    redis: 'healthy',
                    ai_agent: 'healthy',
                    malware_scanner: 'healthy'
                },
            },
        },
    })
    async getHello() {
        const healthStatus = await this.appService.checkHealth();
        return healthStatus;
    }
}