import { Injectable } from '@nestjs/common';
import { DetectionContext } from '../rule-engine/detection-context';
import { graph } from 'src/security/constants';
@Injectable()
export class RuleGraphService {
  async applyGraphAmplification(ctx: DetectionContext): Promise<void> {
    for (const [nodeId, node] of graph) {
      if (!ctx.isTriggered(nodeId)) continue;
      for (const targetId of node.amplifies) {
        if (!ctx.isTriggered(targetId)) continue;
        const target = ctx.ruleResults.get(targetId);
        if (!target) continue;
        const originalScore = target.originalScore;
        const amplified = Math.round(originalScore * (node.amplifyFactor - 1));
        const amplifiedScore = Math.min(100, amplified);
        ctx.ruleResults.set(targetId, {
          ...target,
          amplifiedScore,
          explanation: `${target.explanation} [amplified ×${node.amplifyFactor} by ${nodeId}]`,
        });
      }
    }
  }

  getExecutionOrder(): string[] {
    const visited = new Set<string>();
    const order: string[] = [];
    const visit = (id: string) => {
      if (visited.has(id)) return;
      visited.add(id);
      const node = graph.get(id);
      if (node) {
        for (const dep of node.dependencies) visit(dep);
      }
      order.push(id);
    };
    for (const id of graph.keys()) visit(id);
    return order;
  }
}
