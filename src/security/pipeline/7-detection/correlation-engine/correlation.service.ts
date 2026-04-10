import { Injectable, Logger } from '@nestjs/common';
import { DetectionContext } from '../rule-engine/detection-context';
import { AttackPattern, CorrelationResult } from 'src/security/types';
import { attackPatterns } from 'src/security/constants';

@Injectable()
export class CorrelationService {
  private readonly logger = new Logger(CorrelationService.name);
  async correlate(ctx: DetectionContext): Promise<CorrelationResult> {
    try {
      const matchedPatterns: string[] = [];
      let totalBonus   = 0;
      let descriptions = '';
      for (const pattern of attackPatterns) {
        if (!this.patternMatches(ctx, pattern)) continue;
        matchedPatterns.push(pattern.id);
        totalBonus   += pattern.bonusScore;
        descriptions += `${pattern.name}: ${pattern.description} (+${pattern.bonusScore}pts) | `;
        this.logger.log(`Correlation pattern matched: ${pattern.id}`, {
          emailId: ctx.parsedEmail.emailId,
          bonus:   pattern.bonusScore,
        });
      }
      return {
        patterns:    matchedPatterns,
        bonusScore:  totalBonus,
        description: descriptions,
      };
    } catch (err) {
      this.logger.error('CorrelationService.correlate failed', {
        error: err instanceof Error ? err.message : String(err),
      });
      // non-fatal — empty result
      return { patterns: [], bonusScore: 0, description: '' };
    }
  }
  private patternMatches(ctx: DetectionContext, pattern: AttackPattern): boolean {
    const allRequired = pattern.requiredRules.every(r => ctx.isTriggered(r));
    if (!allRequired) return false;
    if (pattern.optionalRules && pattern.optionalRules.length > 0) {
      return pattern.optionalRules.some(r => ctx.isTriggered(r));
    }
    return true;
  }
}