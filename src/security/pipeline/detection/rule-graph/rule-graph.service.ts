// ─────────────────────────────────────────────────────────────────────────────
// detection/rule-graph/rule-graph.service.ts
//
// Rule Graph Service — models inter-rule dependencies as a directed graph.
//
// Purpose:
//   Some rules are only meaningful when other rules have already fired.
//   The graph enforces evaluation order and dependency resolution.
//
// Example dependency:
//   'conversation_hijacking_attempt' depends on 'email_auth_failure'
//   → both fire → higher combined confidence
//
// The graph is intentionally lightweight — no heavy topological sort library
// needed. A simple dependency adjacency map + BFS ordering suffices.
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable } from '@nestjs/common';
import { DetectionContext } from '../rule-engine/detection-context';

export interface RuleNode {
  id: string;
  dependencies: string[];     // rule IDs that must evaluate first
  amplifies: string[];     // rule IDs whose score is amplified when this fires
  amplifyFactor: number;      // multiplier applied to amplified rules
}

@Injectable()
export class RuleGraphService {
  /**
   * Rule dependency graph.
   * Key: rule ID
   * Value: RuleNode
   */
  private readonly graph: Map<string, RuleNode> = new Map([

    // ── Auth failure يضخّم domain spoofing ───────────────────────────────────
    // المنطق: SPF/DKIM fail + lookalike domain = attacker يتحكم في الـ domain
    // Real world: 94% من phishing emails فيها auth failure (Proofpoint 2024)
    ['email_auth_failure', {
      id: 'email_auth_failure',
      dependencies: [],
      amplifies: ['typosquatting_domain', 'homoglyph_domain_spoofing',
        'lookalike_domain_attack', 'sender_display_name_mismatch',
        'display_name_impersonation', 'reply_to_domain_mismatch'],
      amplifyFactor: 1.3,
    }],

    // ── Display name impersonation يضخّم BEC signals ─────────────────────────
    // المنطق: لو حد بينتحل صفة CEO/CFO + بيطلب فلوس = BEC واضح
    // Real world: FBI IC3 — BEC بيبدأ بـ display name spoofing في 71% من الحالات
    ['display_name_impersonation', {
      id: 'display_name_impersonation',
      dependencies: [],
      amplifies: ['bec_language_detected', 'first_contact_sender_risk',
        'reply_to_domain_mismatch'],
      amplifyFactor: 1.4,
    }],

    // ── BEC language يضخّم first contact risk ────────────────────────────────
    // المنطق: wire transfer request من sender جديد = أخطر بكتير من sender معروف
    ['bec_language_detected', {
      id: 'bec_language_detected',
      dependencies: [],
      amplifies: ['first_contact_sender_risk', 'reply_to_domain_mismatch'],
      amplifyFactor: 1.2,
    }],

    // ── Newly registered domain يضخّم credential harvesting ──────────────────
    // المنطق: domain جديد + credential form = phishing campaign مخطط مسبقاً
    // Real world: 72% من phishing domains بتتسجّل أقل من 24h قبل الهجوم
    ['newly_registered_domain', {
      id: 'newly_registered_domain',
      dependencies: [],
      amplifies: ['credential_harvesting_attempt', 'html_link_text_mismatch',
        'ip_based_url'],
      amplifyFactor: 1.3,
    }],

    // ── Typosquatting يضخّم credential harvesting و brand abuse ──────────────
    // المنطق: lookalike domain + credential form = brand impersonation phishing
    // e.g. paypa1.tk + password form = PayPal phishing campaign
    ['typosquatting_domain', {
      id: 'typosquatting_domain',
      dependencies: [],
      amplifies: ['credential_harvesting_attempt', 'brand_abuse_in_body',
        'urgent_phishing_language'],
      amplifyFactor: 1.3,
    }],

    // ── Malicious URL يضخّم obfuscation signals ──────────────────────────────
    // المنطق: URL confirmed malicious + HTML obfuscation = sophisticated attack
    // Real world: 86% من malspam بيستخدم links مش attachments (BrightDefense 2024)
    ['malicious_url_reputation', {
      id: 'malicious_url_reputation',
      dependencies: [],
      amplifies: ['html_obfuscation_phishing', 'html_link_text_mismatch',
        'base64_encoded_url'],
      amplifyFactor: 1.5,
    }],

    // ── Reputation threat يضخّم domain signals ───────────────────────────────
    // المنطق: IP/domain reputation سيئة + suspicious TLD = infrastructure abuse
    ['suspicious_received_headers', {
      id: 'suspicious_received_headers',
      dependencies: [],
      amplifies: ['typosquatting_domain', 'suspicious_sender_tld',
        'email_auth_failure'],
      amplifyFactor: 1.2,
    }],

  ]);

  /**
   * applyGraphAmplification() — after all rules have evaluated, apply
   * dependency-based score amplifications.
   *
   * When rule A amplifies rule B and both are triggered:
   *   effectiveScore(B) = score(B) × amplifyFactor(A)
   */
  applyGraphAmplification(ctx: DetectionContext): void {
    let phishingDelta = 0;
    let spamDelta = 0;

    for (const [nodeId, node] of this.graph) {
      if (!ctx.isTriggered(nodeId)) continue;

      for (const targetId of node.amplifies) {
        if (!ctx.isTriggered(targetId)) continue;

        const target = ctx.ruleResults.get(targetId);
        if (!target) continue;

        const originalScore = target.score;
        const amplified = Math.round(originalScore * (node.amplifyFactor - 1)); // delta only

        // Apply delta to total scores
        // All amplified rules here are phishing-oriented
        phishingDelta += amplified;

        // Log amplification in explanation
        ctx.ruleResults.set(targetId, {
          ...target,
          score: target.score + amplified,
          explanation: `${target.explanation} [amplified ×${node.amplifyFactor} by ${nodeId}]`,
        });
      }
    }

    if (phishingDelta > 0) {
      ctx.phishingScore = Math.min(100, ctx.phishingScore + phishingDelta);
    }
    if (spamDelta > 0) {
      ctx.spamScore = Math.min(100, ctx.spamScore + spamDelta);
    }
  }

  /**
   * getExecutionOrder() — return rule IDs in dependency-resolved order.
   * Rules with no dependencies come first.
   */
  getExecutionOrder(): string[] {
    const visited = new Set<string>();
    const order: string[] = [];

    const visit = (id: string) => {
      if (visited.has(id)) return;
      visited.add(id);
      const node = this.graph.get(id);
      if (node) {
        for (const dep of node.dependencies) visit(dep);
      }
      order.push(id);
    };

    for (const id of this.graph.keys()) visit(id);
    return order;
  }
}
