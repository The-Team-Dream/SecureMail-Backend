import { Injectable, Logger } from '@nestjs/common';
import { RuleRegistry } from '../rules/rule-registry.service';
import { DetectionContext } from './detection-context';
import { RuleResult } from 'src/security/types';

@Injectable()
export class RuleEngineService {
  private readonly logger = new Logger(RuleEngineService.name);
  constructor(private readonly ruleRegistry: RuleRegistry) { }
  async runRuleEngine(ctx: DetectionContext): Promise<void> {
    const allRules = this.ruleRegistry.getAll();
    let somethingTriggered: boolean;
    do {
      somethingTriggered = false;
      for (const rule of allRules) {
        if (ctx.ruleResults.has(rule.id)) continue;
        if (rule.dependsOn?.some(dep => !ctx.isTriggered(dep))) continue;
        let result: RuleResult;
        try {
          result = await rule.evaluate(ctx);
        } catch (err) {
          this.logger.warn(`Plugin rule "${rule.id}" failed`, {
            error: err instanceof Error ? err.message : String(err),
          });
          continue;
        }
        if (!result.triggered) continue;
        ctx.addResult(result);
        somethingTriggered = true;
      }
    } while (somethingTriggered);
  }
}
