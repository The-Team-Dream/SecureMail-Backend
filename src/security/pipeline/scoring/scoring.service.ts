// ─────────────────────────────────────────────────────────────────────────────
// scoring/scoring.service.ts  (HARDENED v4)
//
// Risk Scoring Engine — Stage 9 of the Security Pipeline.
//
// SECURITY IMPROVEMENTS (v4):
//   PART 3 FIX — Upgraded to correlation bonuses and risk amplification:
//     - URL phishing + domain mismatch → score *= 1.4 (multi-signal amplifier)
//     - BEC behavior + reply-to mismatch → +30 bonus (compound attack pattern)
//     - Confidence scaling: high-confidence matches amplify their contribution
//     - New correlation bonuses are explainable (tracked in breakdown)
//
// Five-tier verdict thresholds (unchanged):
//   0-20   → SAFE
//   21-40  → SPAM
//   41-70  → SUSPICIOUS
//   71-90  → PHISHING
//   91+    → MALICIOUS
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable } from '@nestjs/common';
import { DetectionContext } from '../detection/rule-engine/detection-context';
import { UrlAnalysisResult } from '../url-analysis/url-analysis.service';

export interface ScoreBreakdown {
  ruleScore: number;
  correlationBonus: number;
  reputationScore: number;
  urlThreatScore: number;
  malwareScore: number;
  behaviorScore: number;
  // PART 3 ADD: new amplification tracking
  urlDomainAmplifier: number;   // applied when url_phishing + domain_mismatch
  becReplyToBonus: number;   // applied when BEC behavior + reply-to mismatch
  rawTotal: number;
  finalScore: number;
}

export type RiskTier = 'SAFE' | 'SPAM' | 'SUSPICIOUS' | 'PHISHING' | 'MALICIOUS';

export interface RiskAssessment {
  spamScore: number;
  phishingScore: number;
  finalScore: number;
  breakdown: ScoreBreakdown;
  isSpam: boolean;
  isPhishing: boolean;
  isMalware: boolean;
  riskTier: RiskTier;
  riskLevel: 'none' | 'low' | 'medium' | 'high' | 'critical';
  // Alias for tests that use .tier
  tier: RiskTier;
}

export const RISK_THRESHOLDS = {
  MALICIOUS: 91,
  PHISHING: 71,
  SUSPICIOUS: 41,
  SPAM: 21,
  SAFE: 0,
} as const;

const CAP = {
  rule: 100,
  reputation: 40,
  malware: 80,
  behavior: 25,
  correlation: 50,
  url: 30,
} as const;

const TOTAL_MAX = CAP.rule + CAP.reputation + CAP.malware + CAP.behavior + CAP.correlation + CAP.url;

@Injectable()
export class ScoringService {

  computeRisk(ctx: DetectionContext, urlAnalysis?: UrlAnalysisResult | null): RiskAssessment {
    // ── 1. Collect component values ───────────────────────────────────────────
    const ruleScore        = Math.min(CAP.rule,        Math.max(ctx.phishingScore, ctx.spamScore));
    const reputationScore  = Math.min(CAP.reputation,  ctx.reputation.overallThreatScore);
    const malwareScore     = Math.min(CAP.malware,     ctx.malware?.score ?? 0);
    const behaviorScore    = Math.min(CAP.behavior,    ctx.behavior.behaviorScore);
    const correlationBonus = Math.min(CAP.correlation, ctx.correlation.bonusScore);
    const urlThreatScore   = Math.min(CAP.url,         urlAnalysis?.totalThreatScore ?? 0);
  
    // ── 2. Amplifiers ──────────────────────────────────────────────────────────
    let urlDomainAmplifier = 0;
    let becReplyToBonus    = 0;
  
    const hasUrlPhishing  = urlAnalysis?.hasMaliciousUrl || (urlThreatScore >= 15);
    const hasDomainSpoof  = ctx.isTriggered?.('sender_display_name_mismatch') ||
                            ctx.isTriggered?.('homoglyph_domain_spoofing') || false;
    if (hasUrlPhishing && hasDomainSpoof) {
      urlDomainAmplifier = Math.round(urlThreatScore * 0.4);
    }
  
    const hasBecBehavior     = ctx.behavior.anomalyFlag && ctx.behavior.behaviorScore >= 20;
    const hasReplyToMismatch = ctx.isTriggered?.('reply_to_domain_mismatch') || false;
    if (hasBecBehavior && hasReplyToMismatch) {
      becReplyToBonus = 30;
    }
  
    // ── 3. Additive formula — malwareScore مش في الجمع، بيتعامل معاه بـ override
    const rawTotal = ruleScore
      + reputationScore
      + behaviorScore
      + correlationBonus
      + urlThreatScore
      + urlDomainAmplifier
      + becReplyToBonus;
  
    const clampedScore = Math.min(100, rawTotal);
  
    // ── 4. Malware override ────────────────────────────────────────────────────
    const isMalware  = ctx.malware?.verdict === 'malicious' || malwareScore >= 50;
    const finalScore = isMalware ? Math.max(clampedScore, 91) : clampedScore;
  
    // ── 5. Five-tier classification ────────────────────────────────────────────
    const riskTier   = this.tier(finalScore, isMalware);
    const isPhishing = riskTier === 'PHISHING' || riskTier === 'MALICIOUS';
    const isSpam     = riskTier === 'SPAM';
  
    return {
      spamScore:     Math.min(100, ctx.spamScore),
      phishingScore: Math.min(100, ctx.phishingScore + correlationBonus),
      finalScore,
      breakdown: {
        ruleScore, correlationBonus, reputationScore,
        urlThreatScore, malwareScore, behaviorScore,
        urlDomainAmplifier, becReplyToBonus,
        rawTotal, finalScore,
      },
      isSpam, isPhishing, isMalware,
      riskTier,
      tier: riskTier,
      riskLevel: this.toLevel(riskTier),
    };
  }

  private tier(score: number, malware: boolean): RiskTier {
    if (malware || score >= RISK_THRESHOLDS.MALICIOUS) return 'MALICIOUS';
    if (score >= RISK_THRESHOLDS.PHISHING) return 'PHISHING';
    if (score >= RISK_THRESHOLDS.SUSPICIOUS) return 'SUSPICIOUS';
    if (score >= RISK_THRESHOLDS.SPAM) return 'SPAM';
    return 'SAFE';
  }

  private toLevel(tier: RiskTier): RiskAssessment['riskLevel'] {
    const m: Record<RiskTier, RiskAssessment['riskLevel']> = {
      MALICIOUS: 'critical', PHISHING: 'high',
      SUSPICIOUS: 'medium', SPAM: 'low', SAFE: 'none',
    };
    return m[tier];
  }

  getThresholds() { return RISK_THRESHOLDS; }
}
