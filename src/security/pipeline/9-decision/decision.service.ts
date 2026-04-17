import { Injectable } from '@nestjs/common';
import { FinalVerdict, RiskAssessment, RiskTier, VerdictLabel } from 'src/security/types';
import { DetectionContext } from '../7-detection/rule-engine/detection-context';
import { CONFIDENCE_GATES } from 'src/security/constants';

@Injectable()
export class DecisionService {

  decide(risk: RiskAssessment, ctx: DetectionContext): FinalVerdict {
    const label       = risk.riskTier as VerdictLabel;
    const action      = this.computeAction(label, risk.confidence, risk.isMalware);
    const explanation = this.buildExplanation(label, risk, ctx);
    const details     = this.buildDetails(risk, ctx);
    const recs        = this.buildRecommendations(label, risk, ctx);

    return {
      label,
      riskScore:       risk.finalScore,
      confidence:      risk.confidence,
      action,
      explanation,
      details,
      triggeredRules:  ctx.getTriggeredRuleIds(),
      attackPatterns:  ctx.correlation.patterns,
      recommendations: recs,
    };
  }

  private computeAction(
    label: VerdictLabel,
    confidence: number,
    isMalware: boolean,
  ): FinalVerdict['action'] {
    // Malware confirmed → delete unconditionally
    if (isMalware) return 'delete';
    switch (label) {
      case 'MALICIOUS':
        return confidence >= CONFIDENCE_GATES.delete
          ? 'delete'
          : 'block'; // confident enough إن ده malicious بس مش 100%
      case 'PHISHING':
        return confidence >= CONFIDENCE_GATES.block
          ? 'block'
          : 'quarantine'; // suspicious بس مش confident إنه phishing
      case 'SPAM':
        return 'quarantine';
      case 'SUSPICIOUS':
        return confidence >= CONFIDENCE_GATES.quarantine
          ? 'quarantine'
          : 'allow'; // low confidence suspicious → allow مع details في الـ UI
      default:
        return 'allow';
    }
  }

  // ── Explanation ─────────────────────────────────────────────────────────────
  private buildExplanation(
    label: VerdictLabel,
    risk: RiskAssessment,
    ctx: DetectionContext,
  ): string {
    const patterns = ctx.correlation.patterns
      .map(p => p.replace(/_/g, ' '))
      .join(', ');
    const authSummary = ctx.authResult.hasAuthFailure
      ? ` Authentication failure detected (${ctx.authResult.summary}).`
      : '';
    switch (label) {
      case 'MALICIOUS':
        if (risk.isMalware)
          return `Malicious attachment detected (malware score: ${risk.breakdown.malwareScore}/100). Email blocked.`;
        return `Critical threat detected — risk score: ${risk.finalScore}/100, confidence: ${risk.confidence}%.${authSummary}`;
      case 'PHISHING':
        return patterns
          ? `Phishing detected — patterns: ${patterns}. Risk: ${risk.finalScore}/100 (confidence: ${risk.confidence}%).${authSummary}`
          : `Phishing signals detected across ${ctx.getTriggeredRules().length} security rules. Risk: ${risk.finalScore}/100.${authSummary}`;
      case 'SPAM':
        return `Email classified as spam (spam score: ${risk.spamScore}/100).`;
      case 'SUSPICIOUS':
        return `Suspicious signals detected but below phishing threshold. Risk: ${risk.finalScore}/100, confidence: ${risk.confidence}%. Review recommended.`;
      default:
        return 'No significant threat signals detected.';
    }
  }

  // ── Evidence Details ─────────────────────────────────────────────────────────
  private buildDetails(risk: RiskAssessment, ctx: DetectionContext): string[] {
    const details: string[] = [];

    // Score breakdown summary
    const b = risk.breakdown;
    if (b.authPenalty > 0)
      details.push(`Auth failures: +${b.authPenalty} pts (SPF/DKIM/DMARC)`);
    if (b.reputationScore > 0)
      details.push(`Reputation threat: +${b.reputationScore} pts`);
    if (b.ruleScore > 0)
      details.push(`Rule engine: +${b.ruleScore} pts (${ctx.getTriggeredRules().length} rules triggered)`);
    if (b.behaviorScore > 0)
      details.push(`Behavioral anomaly: +${b.behaviorScore} pts`);
    if (b.correlationBonus > 0)
      details.push(`Correlation bonus: +${b.correlationBonus} pts`);
    if (b.urlThreatScore > 0)
      details.push(`URL threat: +${b.urlThreatScore} pts`);
    if (b.urlDomainAmplifier > 0)
      details.push(`URL + domain spoof amplifier: +${b.urlDomainAmplifier} pts`);
    if (b.becReplyToBonus > 0)
      details.push(`BEC pattern amplifier: +${b.becReplyToBonus} pts`);

    // Top triggered rules (up to 4)
    const topRules = ctx.getTriggeredRules()
      .sort((a, b) => (b.amplifiedScore || 0) - (a.amplifiedScore || 0))
      .slice(0, 4);
    for (const r of topRules) {
      details.push(`[${r.ruleId}] ${r.explanation}`);
    }

    // Attack patterns
    for (const pattern of ctx.correlation.patterns) {
      details.push(`Attack pattern: ${pattern.replace(/_/g, ' ')}`);
    }

    // Confidence note
    if (risk.confidence < 50) {
      details.push(`Note: confidence is ${risk.confidence}% — limited corroborating signals.`);
    }
    return details;
  }

  // ── Recommendations ──────────────────────────────────────────────────────────
  private buildRecommendations(
    label: VerdictLabel,
    risk: RiskAssessment,
    ctx: DetectionContext,
  ): string[] {
    const recs: string[] = [];
    switch (label) {
      case 'MALICIOUS':
        if (risk.isMalware) {
          recs.push('Do not open any attachments from this email.');
          recs.push('Report to your security team immediately.');
          recs.push('Run a malware scan on your device if attachments were already opened.');
        } else {
          recs.push('Do not click any links or reply to this email.');
          recs.push('Report to your security team immediately.');
          recs.push('Delete this email permanently.');
        }
        break;
      case 'PHISHING':
        recs.push('Do not click any links in this email.');
        recs.push('Do not provide any credentials or personal information.');
        if (ctx.isTriggered('credential_harvesting_attempt'))
          recs.push('This email contains a fake login form — entering credentials is dangerous.');
        if (ctx.isTriggered('bec_language_detected'))
          recs.push('Verify any financial requests via a separate channel (phone call).');
        break;
      case 'SPAM':
        recs.push('This appears to be unsolicited commercial email.');
        recs.push('You can safely delete this message.');
        break;
      case 'SUSPICIOUS':
        recs.push('Treat this email with caution before acting on any requests.');
        if (risk.confidence < 50)
          recs.push('Low detection confidence — manual review recommended before taking action.');
        else
          recs.push('Verify sender identity through an alternative channel if needed.');
        break;
      default:
        recs.push('No specific action required.');
    }
    return recs;
  }
}
