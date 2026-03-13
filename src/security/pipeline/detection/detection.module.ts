import { Module }              from '@nestjs/common';
import { ClassificationModule } from '../../../classification/classification.module';
import { RuleEngineService }    from './rule-engine/rule-engine.service';
import { RuleGraphService }     from './rule-graph/rule-graph.service';
import { CorrelationService }   from './correlation-engine/correlation.service';
import { RuleRegistry }         from './rules/rule-registry.service';

@Module({
  imports:   [ClassificationModule],
  providers: [RuleRegistry, RuleEngineService, RuleGraphService, CorrelationService],
  exports:   [RuleRegistry, RuleEngineService, RuleGraphService, CorrelationService],
})
export class DetectionModule {}
