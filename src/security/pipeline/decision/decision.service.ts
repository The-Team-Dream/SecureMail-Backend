// ─────────────────────────────────────────────────────────────────────────────
// decision/decision.service.ts
//
// Decision Engine — Stage 10 of the Security Pipeline.
//
// Converts the RiskAssessment into a final human-readable verdict and
// recommended action. This is the final stage before post-delivery protection.
//
// Verdict categories: SAFE | SPAM | SUSPICIOUS | PHISHING | MALICIOUS
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable } from '@nestjs/common';
import { RiskAssessment, RiskTier } from '../scoring/scoring.service';
import { DetectionContext } from '../detection/rule-engine/detection-context';
import { CorrelationResult } from '../detection/rule-engine/detection-context';

// ─── Verdict ──────────────────────────────────────────────────────────────────
export type VerdictLabel = 'SAFE' | 'SPAM' | 'SUSPICIOUS' | 'PHISHING' | 'MALICIOUS';

export interface FinalVerdict {
  label: VerdictLabel;
  riskScore: number;
  confidence: number;      // 0-100
  action: 'allow' | 'quarantine' | 'block' | 'delete';
  explanation: string;      // one-sentence summary for user
  details: string[];    // array of evidence points
  triggeredRules: string[];
  attackPatterns: string[];
  recommendations: string[];
}

@Injectable()
export class DecisionService {
  /**
   * decide() — converts risk assessment into final verdict.
   */
  decide(
    risk: RiskAssessment,
    ctx: DetectionContext,
    correlation: CorrelationResult,
  ): FinalVerdict {
    const label = this.computeLabel(risk);
    const action = this.computeAction(label, risk);
    const confidence = this.computeConfidence(risk, ctx);
    const explanation = this.buildExplanation(label, risk, ctx, correlation);
    const details = this.buildDetails(risk, ctx, correlation);
    const recs = this.buildRecommendations(label, risk, ctx);

    return {
      label,
      riskScore: risk.finalScore,
      confidence,
      action,
      explanation,
      details,
      triggeredRules: ctx.getTriggeredRuleIds(),
      attackPatterns: correlation.patterns,
      recommendations: recs,
    };
  }

  // ─── Label computation ────────────────────────────────────────────────────
  private computeLabel(risk: RiskAssessment): VerdictLabel {
    // Use the authoritative five-tier classification from ScoringService
    const tierMap: Record<RiskTier, VerdictLabel> = {
      MALICIOUS: 'MALICIOUS',
      PHISHING: 'PHISHING',
      SUSPICIOUS: 'SUSPICIOUS',
      SPAM: 'SPAM',
      SAFE: 'SAFE',
    };
    return tierMap[risk.riskTier] ?? 'SAFE';
  }

  // ─── Action mapping ───────────────────────────────────────────────────────
  private computeAction(label: VerdictLabel, risk: RiskAssessment): FinalVerdict['action'] {
    switch (label) {
      case 'MALICIOUS': return 'delete';
      case 'PHISHING': return 'block';
      case 'SPAM': return 'quarantine';
      case 'SUSPICIOUS': return risk.finalScore >= 50 ? 'quarantine' : 'allow';
      default: return 'allow';
    }
  }

  // ─── Confidence computation ───────────────────────────────────────────────
  // FIX-8: Confidence يحسب بدقة أكتر
  // المشكلة القديمة: 5+ rules → 90% flat بغض النظر عن نوع الـ attack
  // BEC attack بـ 2 rules بس كان يدي 70% مع إنه high-confidence attack
  //
  // الحل الجديد:
  //   1. Base من rule count (كالعادة)
  //   2. كل attack pattern مكتشف = +15 (مش +10 flat)
  //   3. Critical patterns (bec_attack، phishing_campaign) = +5 إضافية
  //   4. High-score عالي مع few rules = confidence boost (score يدل على certainty)
  private computeConfidence(risk: RiskAssessment, ctx: DetectionContext): number {
    // Malware = near-certain دايماً
    if (risk.isMalware) return 95;

    const triggeredCount = ctx.getTriggeredRules().length;

    // ── Base confidence from corroborating rule count ─────────────────────────
    let base = 50;
    if (triggeredCount >= 5) base = 85;
    else if (triggeredCount >= 3) base = 75;
    else if (triggeredCount >= 2) base = 65;
    else if (triggeredCount >= 1) base = 55;

    // ── FIX-8: Attack pattern boost — per pattern، not flat ──────────────────
    const CRITICAL_PATTERNS = new Set([
      'bec_attack', 'phishing_campaign', 'malware_social_engineering',
    ]);
    const HIGH_PATTERNS = new Set([
      'brand_spoofing_attack', 'auth_bypass_spoofing',
      'conversation_hijacking', 'advanced_obfuscated_phishing',
    ]);

    for (const pattern of ctx.correlation.patterns) {
      if (CRITICAL_PATTERNS.has(pattern)) {
        base += 20; // BEC أو phishing campaign مكتملة = boost كبير
      } else if (HIGH_PATTERNS.has(pattern)) {
        base += 12;
      } else {
        base += 8;  // any other pattern
      }
    }

    // ── FIX-8: High score + few rules = still confident (strong single signal) ─
    // مثلاً: malware attachment بدون body signals → score عالي، rules قليلة
    if (risk.finalScore >= 80 && triggeredCount <= 2) {
      base += 10;
    }

    return Math.min(95, base);
  }

  // ─── Explanation ──────────────────────────────────────────────────────────
  private buildExplanation(
    label: VerdictLabel,
    risk: RiskAssessment,
    ctx: DetectionContext,
    correlation: CorrelationResult,
  ): string {
    const patterns = correlation.patterns.map(p => p.replace(/_/g, ' ')).join(', ');

    switch (label) {
      case 'MALICIOUS':
        if (risk.isMalware && risk.breakdown.malwareScore > 0)
          return `This email contains a malicious attachment (malware score: ${risk.breakdown.malwareScore}). It has been blocked.`;
        return `This email has been identified as a critical threat (risk score: ${risk.finalScore}) based on ${ctx.getTriggeredRules().length} security signals. It has been blocked.`;
      case 'PHISHING':
        return patterns
          ? `Phishing detected — attack patterns identified: ${patterns} (risk score: ${risk.finalScore}).`
          : `Phishing detected based on ${ctx.getTriggeredRules().length} triggered security rules (risk score: ${risk.finalScore}).`;
      case 'SPAM':
        return `Email classified as spam (spam score: ${risk.spamScore}).`;
      case 'SUSPICIOUS':
        return `Email has suspicious signals but below phishing threshold. Review recommended (risk score: ${risk.finalScore}).`;
      case 'SAFE':
        return 'No significant threat signals detected.';
    }
  }

  // ─── Evidence details ──────────────────────────────────────────────────────
  private buildDetails(
    risk: RiskAssessment,
    ctx: DetectionContext,
    correlation: CorrelationResult,
  ): string[] {
    const details: string[] = [];

    // Top triggered rules (up to 5)
    const triggered = ctx.getTriggeredRules()
      .sort((a, b) => b.score - a.score)
      .slice(0, 5);

    for (const r of triggered) {
      details.push(`[${r.ruleId}] ${r.explanation} (score: ${r.score})`);
    }

    // Authentication summary
    if (ctx.authResult.hasAuthFailure) {
      details.push(`Authentication: ${ctx.authResult.summary}`);
    }

    // Attack patterns
    for (const pattern of correlation.patterns) {
      details.push(`Attack pattern: ${pattern.replace(/_/g, ' ')} (+${correlation.bonusScore} pts)`);
    }

    // Reputation
    if (ctx.reputation.overallThreatScore > 0) {
      details.push(`Reputation threat score: ${ctx.reputation.overallThreatScore} — ${ctx.reputation.details}`);
    }

    // Behavioral
    if (ctx.behavior.anomalyFlag) {
      details.push(`Behavioral anomaly: ${ctx.behavior.anomalyDescription}`);
    }

    return details;
  }

  // ─── Recommendations ──────────────────────────────────────────────────────
  private buildRecommendations(
    label: VerdictLabel,
    risk: RiskAssessment,
    ctx: DetectionContext,
  ): string[] {
    const recs: string[] = [];

    switch (label) {
      case 'MALICIOUS':
        if (risk.isMalware && risk.breakdown.malwareScore > 0) {
          recs.push('Do not open any attachments from this email.');
          recs.push('Report this email to your security team immediately.');
          recs.push('Check your device for malware if you already opened attachments.');
        } else {
          recs.push('Do not click any links or reply to this email.');
          recs.push('Report this email to your security team immediately.');
          recs.push('Delete this email permanently.');
        }
        break;
      case 'PHISHING':
        recs.push('Do not click any links in this email.');
        recs.push('Do not provide any credentials or personal information.');
        if (ctx.isTriggered('credential_harvesting_attempt')) {
          recs.push('This email contains a fake login form — entering credentials here is dangerous.');
        }
        if (ctx.isTriggered('bec_language_detected')) {
          recs.push('Verify any financial requests through a separate communication channel (phone call).');
        }
        break;
      case 'SPAM':
        recs.push('This email appears to be unsolicited commercial email.');
        recs.push('You can safely delete this message.');
        break;
      case 'SUSPICIOUS':
        recs.push('Treat this email with caution before acting on any requests.');
        recs.push('Verify the sender identity through an alternative channel if needed.');
        break;
      default:
        recs.push('No specific action required.');
    }

    return recs;
  }
}
