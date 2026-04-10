import { Module }         from '@nestjs/common';
import { BehaviorService } from './behavior.service';
import { PrismaModule }    from '../../../prisma.module';

@Module({
  imports:   [PrismaModule],
  providers: [BehaviorService],
  exports:   [BehaviorService],
})
export class BehaviorModule {}
