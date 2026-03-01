import { Module } from '@nestjs/common';
import { FoldersService } from './folders.service';
import { PrismaModule } from '../prisma.module';

@Module({
  imports: [PrismaModule],
  providers: [FoldersService],
})
export class FoldersModule {}
