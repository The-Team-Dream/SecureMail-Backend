// ─────────────────────────────────────────────────────────────────────────────
// detection/correlation-engine/correlation.service.ts
//
// Correlation Engine — detects complex attack patterns from rule combinations.
//
// A pattern fires when ALL its required rules are triggered simultaneously.
// Pattern detection significantly boosts the final risk score because
// multiple corroborating signals reduce false-positive risk.
//
// Patterns are defined declaratively (support YAML-like structure) so they
// can be updated without code changes.
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable, Logger } from '@nestjs/common';
import { DetectionContext, CorrelationResult } from '../rule-engine/detection-context';

// ─── Attack Pattern Definition ────────────────────────────────────────────────
export interface AttackPattern {
  id: string;
  name: string;
  description: string;
  // ALL of these rules must be triggered
  requiredRules: string[];
  // AT LEAST ONE of these additional rules (optional amplifier)
  optionalRules?: string[];
  // Score bonus applied to phishingScore when pattern matches
  bonusScore: number;
  // Severity classification
  severity: 'critical' | 'high' | 'medium';
}

@Injectable()
export class CorrelationService {
  private readonly logger = new Logger(CorrelationService.name);

  // ─── Attack Pattern Library ────────────────────────────────────────────────
  // Patterns can be loaded from YAML in a future iteration (infrastructureRules
  // stub supports this). For now, defined programmatically.
  private readonly patterns: AttackPattern[] = [

    // ── 1. BEC — Business Email Compromise ───────────────────────────────────
    // Real world: attacker impersonates CEO/CFO — NO links, NO attachments.
    // Reply-To mismatch = "CFO fraud" pattern — replies go to attacker's mailbox.
    // FBI IC3 2024: $2.77B losses, 53% of all phishing attacks were BEC.
    {
      id: 'bec_attack',
      name: 'Business Email Compromise',
      description: 'Executive impersonation with financial pressure — no links or attachments',
      requiredRules: ['bec_language_detected'],
      optionalRules: ['reply_to_domain_mismatch', 'first_contact_sender_risk',
        'email_auth_failure', 'display_name_impersonation', 'sender_display_name_mismatch'],
      bonusScore: 30,
      severity: 'critical',
    },

    // ── 2. Credential Phishing Campaign ──────────────────────────────────────
    // Real world: fake login pages via forms/password fields — 66% of phishing
    // attempts use credential theft (Hoxhunt 2025).
    {
      id: 'phishing_campaign',
      name: 'Credential Phishing Campaign',
      description: 'Urgent language + credential harvesting form targeting victim login',
      requiredRules: ['urgent_phishing_language', 'credential_harvesting_attempt'],
      optionalRules: ['typosquatting_domain', 'email_auth_failure', 'suspicious_sender_tld',
        'newly_registered_domain', 'sender_display_name_mismatch',
        'html_obfuscation_phishing', 'ip_based_url'],
      bonusScore: 25,
      severity: 'critical',
    },

    // ── 3. Brand Spoofing / Impersonation ─────────────────────────────────────
    // Real world: 60%+ of phishing emails impersonate a known brand (Hoxhunt 2025).
    // homoglyph = Unicode trick e.g. "paypaӏ.com" (Cyrillic ӏ vs Latin l).
    {
      id: 'brand_spoofing_attack',
      name: 'Brand Spoofing / Impersonation',
      description: 'Lookalike domain or homoglyph combined with brand abuse in body',
      requiredRules: ['brand_abuse_in_body'],
      optionalRules: ['typosquatting_domain', 'homoglyph_domain_spoofing',
        'lookalike_domain_attack', 'sender_display_name_mismatch',
        'suspicious_sender_tld', 'email_auth_failure'],
      bonusScore: 20,
      severity: 'high',
    },

    // ── 4. Auth Bypass Spoofing ───────────────────────────────────────────────
    // Real world: attacker spoofs display name but SPF/DKIM fail — common in
    // cheap phishing kits. AiTM attacks surged 146% in 2024 show same pattern.
    {
      id: 'auth_bypass_spoofing',
      name: 'Authentication Bypass Spoofing',
      description: 'SPF/DKIM/DMARC failure combined with display name impersonation',
      requiredRules: ['email_auth_failure', 'sender_display_name_mismatch'],
      optionalRules: ['typosquatting_domain', 'suspicious_sender_tld',
        'display_name_impersonation', 'reply_to_domain_mismatch',
        'newly_registered_domain'],
      bonusScore: 25,
      severity: 'high',
    },

    // ── 5. Conversation Hijacking ─────────────────────────────────────────────
    // Real world: attacker intercepts payment thread, replies from lookalike domain.
    // VEC attacks rose 66% in H1 2024.
    {
      id: 'conversation_hijacking',
      name: 'Conversation Hijacking',
      description: 'Financial request injected into an existing reply thread',
      requiredRules: ['conversation_hijacking_attempt'],
      optionalRules: ['bec_language_detected', 'reply_to_domain_mismatch',
        'email_auth_failure', 'typosquatting_domain'],
      bonusScore: 20,
      severity: 'high',
    },

    // ── 6. Advanced Obfuscated Phishing ──────────────────────────────────────
    // Real world: kits hide URLs via base64/HTML tricks to bypass email gateways.
    // 86% of malspam in 2024 used links over attachments.
    {
      id: 'advanced_obfuscated_phishing',
      name: 'Advanced Obfuscated Phishing',
      description: 'HTML/encoding tricks to hide malicious links from email scanners',
      requiredRules: ['html_obfuscation_phishing'],
      optionalRules: ['base64_encoded_url', 'html_link_text_mismatch',
        'ip_based_url', 'malicious_url_reputation'],
      bonusScore: 20,
      severity: 'high',
    },

    // ── 7. Malware Delivery via Social Engineering ────────────────────────────
    // Real world: ZIP (62%), DOCM (16%), XLSX (10%) — top malicious attachment
    // types in 2024. Urgency = pressure to open file.
    {
      id: 'malware_social_engineering',
      name: 'Malware Delivery via Social Engineering',
      description: 'Malicious attachment combined with urgent or BEC pressure tactics',
      requiredRules: ['risky_attachment_detected'],
      optionalRules: ['urgent_phishing_language', 'bec_language_detected',
        'first_contact_sender_risk', 'email_auth_failure'],
      bonusScore: 25,
      severity: 'critical',
    },

    // ── 8. Infrastructure Abuse ───────────────────────────────────────────────
    // Real world: rogue/compromised mail servers that don't match claimed sender.
    // Suspicious received headers + auth failure = hijacked sending infrastructure.
    {
      id: 'infrastructure_abuse',
      name: 'Infrastructure Abuse',
      description: 'Rogue mail server with auth failures — compromised sending infrastructure',
      requiredRules: ['suspicious_received_headers', 'email_auth_failure'],
      optionalRules: ['typosquatting_domain', 'newly_registered_domain',
        'suspicious_sender_tld', 'malicious_url_reputation'],
      bonusScore: 15,
      severity: 'high',
    },
  ];

  /**
   * correlate() — scan all patterns against triggered rules.
   * Returns a CorrelationResult with matched patterns and total bonus score.
   */
  correlate(ctx: DetectionContext): CorrelationResult {
    try {
      return this.doCorrelate(ctx);
    } catch (err) {
      this.logger.error('CorrelationService.correlate failed', {
        error: err instanceof Error ? err.message : String(err),
      });
      return { patterns: [], bonusScore: 0, description: '' };
    }
  }

  private doCorrelate(ctx: DetectionContext): CorrelationResult {
    const matchedPatterns: string[] = [];
    let totalBonus = 0;
    const descriptions: string[] = [];

    for (const pattern of this.patterns) {
      if (!this.patternMatches(ctx, pattern)) continue;

      matchedPatterns.push(pattern.id);
      totalBonus += pattern.bonusScore;
      descriptions.push(`${pattern.name}: ${pattern.description} (+${pattern.bonusScore}pts)`);

      this.logger.log(`Correlation pattern matched: ${pattern.id}`, {
        emailId: ctx.parsedEmail.emailId,
        bonus: pattern.bonusScore,
      });
    }

    return {
      patterns: matchedPatterns,
      bonusScore: Math.min(50, totalBonus), // cap bonus at 50 to prevent runaway scores
      description: descriptions.join(' | '),
    };
  }

  private patternMatches(ctx: DetectionContext, pattern: AttackPattern): boolean {
    // All required rules must be triggered
    const allRequired = pattern.requiredRules.every(r => ctx.isTriggered(r));
    if (!allRequired) return false;

    // If optional rules defined: at least one must be triggered
    if (pattern.optionalRules && pattern.optionalRules.length > 0) {
      const anyOptional = pattern.optionalRules.some(r => ctx.isTriggered(r));
      if (!anyOptional) return false;
    }

    return true;
  }

  /** Expose patterns for testing and DSL extension */
  getPatterns(): AttackPattern[] {
    return this.patterns;
  }

  /** Add a pattern at runtime (supports YAML-loaded patterns) */
  addPattern(pattern: AttackPattern): void {
    this.patterns.push(pattern);
  }
}
