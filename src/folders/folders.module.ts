import { Module } from '@nestjs/common';
import { FoldersService } from './folders.service';

@Module({
  providers: [FoldersService]
})
export class FoldersModule {}
