import { Injectable } from '@nestjs/common';
import { DetectionContext } from '../7-detection/rule-engine/detection-context';
import { RiskAssessment, RiskTier, ScoreBreakdown } from 'src/security/types';
import { AuthSignals } from 'src/security/types/auth.types';
import { AMPLIFIER_BASE_THRESHOLD, RISK_THRESHOLDS, RULE_MATURITY_FACTOR, TIER_CAPS } from 'src/security/constants';

@Injectable()
export class ScoringService {

  computeRisk(ctx: DetectionContext): RiskAssessment {

    // OVERRIDE GATE: Malware or URL malicious = MALICIOUS
    const isMalware = ctx.malware?.verdict === 'malicious' || (ctx.malware?.score ?? 0) >= 50;
    const isUrlMalicious = ctx.urlResult?.hasMaliciousUrl === true;

    if (isMalware || isUrlMalicious) {
      return this.buildMaliciousOverride(ctx, isMalware, isUrlMalicious);
    }

    // ══════════════════════════════════════════════════════════════════════════
    // TIER 1 — HARD SIGNALS (Auth + Reputation)
    // High trust — ده اللي بنبني عليه كل حاجة
    // ══════════════════════════════════════════════════════════════════════════

    // Auth Penalty — SPF/DKIM/DMARC failures
    const authPenalty = this.computeAuthPenalty(ctx.authResult);

    // Reputation — IP + Domain منفصلين مع bonus لو الاتنين عاليين
    const ipScore = ctx.reputation.ipReputationScore ?? 0;
    const domainScore = ctx.reputation.domainReputationScore ?? 0;
    const bothHighBonus = (ipScore >= 20 && domainScore >= 20) ? 8 : 0;
    const reputationScore = Math.min(
      TIER_CAPS.reputation,
      Math.max(ipScore, domainScore) + bothHighBonus,
    );

    const tier1Score = authPenalty + reputationScore; // max ~90

    // ══════════════════════════════════════════════════════════════════════════
    // TIER 2 — SOFT SIGNALS (Rules + Behavior)
    // Rules: مضروبة في RULE_MATURITY_FACTOR عشان نحمي من false positives
    // Behavior: per-user، أكتر ثقة من الـ rules
    // ══════════════════════════════════════════════════════════════════════════

    // Rule Score — weighted blend (70% phishing + 30% spam)
    // بناخد blend مش max عشان ميضيعش signal لو الاتنين عاليين
    let phishingScore = 0;
    let spamScore = 0;
    for (const rule of ctx.ruleResults.values()) {
      if (!rule.triggered) continue;
      if (rule.scoreTarget === 'phishing' || rule.scoreTarget === 'both') {
        phishingScore += rule.amplifiedScore;
      } else if (rule.scoreTarget === 'spam') {
        spamScore += rule.amplifiedScore;
      }
    }
    const rawRuleScore = Math.round(phishingScore * 0.7 + spamScore * 0.3);
    const ruleScore = Math.min(
      TIER_CAPS.rules,
      Math.round(rawRuleScore * RULE_MATURITY_FACTOR),
    );

    const behaviorScore = Math.min(TIER_CAPS.behavior, ctx.behavior.behaviorScore);

    const tier2Score = ruleScore + behaviorScore; // max ~85

    // ══════════════════════════════════════════════════════════════════════════
    // TIER 3 — AMPLIFIERS (Correlation + URL)
    // بيشتغلوا بالكامل بس لو في base signal كافي من Tier 1 أو Tier 2
    // من غير base → max 10 بس عشان نمنع false positives
    // ══════════════════════════════════════════════════════════════════════════

    const urlThreatScore = Math.min(TIER_CAPS.url, ctx.urlResult?.totalThreatScore ?? 0);

    const baseIsSignificant = (tier1Score + tier2Score) >= AMPLIFIER_BASE_THRESHOLD;
    const correlationBonus = baseIsSignificant
      ? Math.min(TIER_CAPS.correlation, ctx.correlation.bonusScore)
      : Math.min(10, ctx.correlation.bonusScore);

    // URL + Domain Spoof Amplifier
    const hasUrlThreat = urlThreatScore >= 15;
    const hasDomainSpoof = ctx.isTriggered('sender_display_name_mismatch') ||
      ctx.isTriggered('homoglyph_domain_spoofing');
    const urlDomainAmplifier = (hasUrlThreat && hasDomainSpoof)
      ? Math.min(TIER_CAPS.urlDomainAmplifier, Math.round(urlThreatScore * 0.4))
      : 0;

    // BEC Amplifier — behavioral anomaly + reply-to mismatch
    const hasBecBehavior = (ctx.behavior.anomalyFlag ?? false) && behaviorScore >= 15;
    const hasReplyToMismatch = ctx.isTriggered('reply_to_domain_mismatch');
    const becReplyToBonus = (hasBecBehavior && hasReplyToMismatch)
      ? TIER_CAPS.becReplyToBonus
      : 0;

    const tier3Score = correlationBonus + urlThreatScore + urlDomainAmplifier + becReplyToBonus;

    // ══════════════════════════════════════════════════════════════════════════
    // FINAL SCORE
    // ══════════════════════════════════════════════════════════════════════════
    const rawTotal = tier1Score + tier2Score + tier3Score;
    const finalScore = Math.min(100, rawTotal);

    // ══════════════════════════════════════════════════════════════════════════
    // TIER CLASSIFICATION + CONFIDENCE
    // ══════════════════════════════════════════════════════════════════════════
    const riskTier = this.computeTier(finalScore);
    const confidence = this.computeConfidence(finalScore, tier1Score, tier2Score, ctx);

    const isPhishing = riskTier === 'PHISHING' || riskTier === 'MALICIOUS';
    const isSpam = riskTier === 'SPAM';

    const breakdown: ScoreBreakdown = {
      // Tier 1
      authPenalty,
      reputationScore,
      // Tier 2
      ruleScore,
      behaviorScore,
      // Tier 3
      correlationBonus,
      urlThreatScore,
      urlDomainAmplifier,
      becReplyToBonus,
      // Malware (للـ breakdown فقط — مش في الـ sum)
      malwareScore: ctx.malware?.score ?? 0,
      // Totals
      rawTotal,
      finalScore,
    };

    return {
      spamScore: Math.min(100, spamScore),
      phishingScore: Math.min(100, phishingScore + correlationBonus),
      finalScore,
      breakdown,
      isSpam,
      isPhishing,
      isMalware: false,
      riskTier,
      tier: riskTier,
      riskLevel: this.toLevel(riskTier),
      confidence,
    };
  }

  // ══════════════════════════════════════════════════════════════════════════
  // OVERRIDE BUILDER
  // لما Malware أو URL malicious يتأكد — بنبني الـ result مباشرة
  // ══════════════════════════════════════════════════════════════════════════
  private buildMaliciousOverride(
    ctx: DetectionContext,
    isMalware: boolean,
    isUrlMalicious: boolean,
  ): RiskAssessment {
    // بنحسب الـ scores العادية للـ breakdown بس — مش بتأثر على الـ verdict
    const authPenalty = this.computeAuthPenalty(ctx.authResult);
    const reputationScore = Math.min(
      TIER_CAPS.reputation,
      Math.max(
        ctx.reputation.ipReputationScore ?? 0,
        ctx.reputation.domainReputationScore ?? 0,
      ),
    );
    const malwareScore = ctx.malware?.score ?? 0;
    const urlThreatScore = Math.min(TIER_CAPS.url, ctx.urlResult?.totalThreatScore ?? 0);

    // Override score: malware = 95، URL malicious = 91
    const finalScore = isMalware ? 95 : 91;

    const breakdown: ScoreBreakdown = {
      authPenalty,
      reputationScore,
      ruleScore: 0,
      behaviorScore: 0,
      correlationBonus: 0,
      urlThreatScore,
      urlDomainAmplifier: 0,
      becReplyToBonus: 0,
      malwareScore,
      rawTotal: finalScore,
      finalScore,
    };

    return {
      spamScore: 0,
      phishingScore: 0,
      finalScore,
      breakdown,
      isSpam: false,
      isPhishing: true,
      isMalware: true,
      riskTier: 'MALICIOUS',
      tier: 'MALICIOUS',
      riskLevel: 'critical',
      confidence: 95, // malware/url confirmed = near-certain
    };
  }

  // ══════════════════════════════════════════════════════════════════════════
  // AUTH PENALTY
  // SPF/DKIM/DMARC failures = real signals مش بس flags
  // Triple failure = extra penalty لأن ده signature خاصة بالـ spoofed senders
  // ══════════════════════════════════════════════════════════════════════════
  private computeAuthPenalty(auth: AuthSignals): number {
    let penalty = 0;

    // SPF
    if (auth.spf.status === 'fail') penalty += 20;
    else if (auth.spf.status === 'softfail') penalty += 10;
    else if (auth.spf.status === 'none') penalty += 4;

    // DKIM
    if (auth.dkim.status === 'fail') penalty += 20;
    else if (auth.dkim.status === 'none') penalty += 4;

    // DMARC
    if (auth.dmarc.status === 'fail') penalty += 15;
    else if (auth.dmarc.status === 'none') penalty += 3;

    // Triple failure bonus — كلهم فشلوا = likely spoofed sender
    const allFailed =
      auth.spf.status === 'fail' &&
      auth.dkim.status === 'fail' &&
      auth.dmarc.status === 'fail';
    if (allFailed) penalty += 15;

    return Math.min(TIER_CAPS.auth, penalty);
  }

  // ══════════════════════════════════════════════════════════════════════════
  // CONFIDENCE RESOLVER
  // بيحسب إزاي الـ tiers بتدعم بعض — مش بس عدد الـ rules
  //
  //  HIGH   (85–95%) → Tier 1 + Tier 2 كلاهما يشيروا لنفس الاتجاه
  //  MEDIUM (65–84%) → Tier 1 أو Tier 2 واحد منهم بس قوي
  //  LOW    (40–64%) → Tier 3 هو اللي رفع الـ score
  //  VERY LOW (<40%) → signal واحد أو behavior بس
  // ══════════════════════════════════════════════════════════════════════════
  private computeConfidence(
    finalScore: number,
    tier1Score: number,
    tier2Score: number,
    ctx: DetectionContext,
  ): number {
    let confidence = 40; // base

    // Tier 1 contribution — high trust signals
    if (tier1Score >= 50) confidence += 35;
    else if (tier1Score >= 30) confidence += 25;
    else if (tier1Score >= 15) confidence += 15;
    else if (tier1Score >= 5) confidence += 8;

    // Tier 2 contribution — lower trust، أقل تأثير على الـ confidence
    if (tier2Score >= 40) confidence += 20;
    else if (tier2Score >= 20) confidence += 12;
    else if (tier2Score >= 10) confidence += 6;

    // Cross-tier corroboration bonus
    // لو Tier 1 و Tier 2 الاتنين بيشيروا لنفس الاتجاه = أكيد أكتر
    const tier1Strong = tier1Score >= 20;
    const tier2Strong = tier2Score >= 15;
    if (tier1Strong && tier2Strong) confidence += 15;

    // Attack pattern corroboration
    const CRITICAL_PATTERNS = new Set([
      'bec_attack', 'phishing_campaign', 'malware_social_engineering',
    ]);
    for (const pattern of ctx.correlation.patterns) {
      confidence += CRITICAL_PATTERNS.has(pattern) ? 10 : 5;
    }

    // Safe email — high score مع zero Tier 1 = lower confidence
    // (ممكن يكون false positive من rules immature)
    if (finalScore >= 75 && tier1Score < 10) {
      confidence -= 20;
    }

    return Math.min(95, Math.max(10, confidence));
  }

  // ══════════════════════════════════════════════════════════════════════════
  // HELPERS
  // ══════════════════════════════════════════════════════════════════════════
  private computeTier(score: number): RiskTier {
    if (score >= RISK_THRESHOLDS.MALICIOUS) return 'MALICIOUS';
    if (score >= RISK_THRESHOLDS.PHISHING) return 'PHISHING';
    if (score >= RISK_THRESHOLDS.SUSPICIOUS) return 'SUSPICIOUS';
    if (score >= RISK_THRESHOLDS.SPAM) return 'SPAM';
    return 'SAFE';
  }

  private toLevel(tier: RiskTier): RiskAssessment['riskLevel'] {
    const map: Record<RiskTier, RiskAssessment['riskLevel']> = {
      MALICIOUS: 'critical',
      PHISHING: 'high',
      SUSPICIOUS: 'medium',
      SPAM: 'low',
      SAFE: 'none',
    };
    return map[tier];
  }

  getThresholds() { return RISK_THRESHOLDS; }
}