import { Module } from '@nestjs/common';
import { DecisionService } from './decision.service';

@Module({
  providers: [DecisionService],
  exports:   [DecisionService],
})
export class DecisionModule {}
