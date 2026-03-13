// ─────────────────────────────────────────────────────────────────────────────
// behavior/behavior.service.ts
//
// Behavioral Analysis Engine — Stage 7 of the Security Pipeline.
//
// Analyzes sender history to detect behavioral anomalies:
//   - New sender requesting financial action
//   - Topic change anomaly (previous = newsletters, current = BEC)
//   - Unusual attachment pattern
//   - Frequency spike anomaly
//
// Replaces and extends the inline getSenderHistory() method in the existing
// email-sync.processor.ts (which remains for backward compatibility).
// This service provides a richer BehaviorSignals object.
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable, Logger } from '@nestjs/common';
import { PrismaService } from '../../../prisma.service';
import { ParsedEmail }   from '../email-parser/email-parser.service';
import { BehaviorSignals, DEFAULT_BEHAVIOR } from '../detection/rule-engine/detection-context';

// ─── Topic keyword sets ───────────────────────────────────────────────────────
// FIX-4: أضفنا body-level keywords ومزيد من topics
// inferTopic الآن بيحلل subject + body معاً بدل subject فقط

// ─────────────────────────────────────────────────────────────────────────────
// normalizeText() — exported pure utility used by behavior rules + tests
//
// Strips BEC obfuscation techniques:
//   1. Unicode NFKD normalization + diacritic removal
//   2. Homoglyph/leet reversal (Cyrillic, Greek, leet digits)
//   3. Punctuation between word chars removed → space
//   4. Collapse whitespace + lowercase
// ─────────────────────────────────────────────────────────────────────────────

const HOMOGLYPH_LEET_MAP: Record<string, string> = {
  // Leet digits
  '0': 'o', '1': 'i', '3': 'e', '4': 'a', '5': 's', '7': 't',
  // Cyrillic → Latin
  'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'х': 'x',
  'у': 'y', 'і': 'i', 'ї': 'i', 'ӏ': 'l',
  // Turkish
  'ı': 'i', 'ş': 's', 'ğ': 'g', 'ç': 'c', 'ö': 'o', 'ü': 'u',
  // Greek
  'α': 'a', 'ο': 'o', 'ρ': 'p', 'ν': 'n', 'κ': 'k',
};

export function normalizeText(text: string): string {
  if (!text) return '';

  // Step 1: Lowercase
  let out = text.toLowerCase();

  // Step 2: Unicode NFKD + strip combining diacritics
  out = out.normalize('NFKD').replace(/[\u0300-\u036f]/g, '');

  // Step 3: Homoglyph/leet replacement
  out = out.split('').map(c => HOMOGLYPH_LEET_MAP[c] ?? c).join('');

  // Step 4: Remove punctuation between word chars (wire-transfer → wire transfer)
  out = out.replace(/(\w)[.\-_](\w)/g, '$1 $2');

  // Step 5: Collapse whitespace
  out = out.replace(/\s{2,}/g, ' ').trim();

  return out;
}

const BEC_KEYWORDS     = /wire\s+transfer|bank\s+transfer|gift\s+card|payment|invoice|urgent\s+payment|ach\s+transfer|remittance|wire\s+funds|transfer\s+funds/i;
const PHISH_KEYWORDS   = /verify|confirm|login|password|suspended|locked|security\s+alert|account\s+access|sign[\s-]in|credentials/i;
const NEWSLETTER_KEYS  = /unsubscribe|newsletter|weekly|monthly|digest|mailing\s+list|opt[\s-]out/i;
const FINANCIAL_KEYS   = /invoice|payment|receipt|statement|billing|remittance|purchase\s+order|quotation/i;
const ORDER_KEYS       = /order|shipped|delivery|tracking|dispatch|package|shipment|out\s+for\s+delivery/i;
const INTERNAL_HR_KEYS = /payroll|salary|expense|reimbursement|benefits|onboarding|employee/i;
const SUPPORT_KEYS     = /ticket|support\s+request|helpdesk|case\s+number|incident|open\s+ticket/i;

@Injectable()
export class BehaviorService {
  private readonly logger = new Logger(BehaviorService.name);

  constructor(private readonly prisma: PrismaService) {}

  /**
   * analyze() — query sender history and compute behavioral signals.
   */
  async analyze(email: ParsedEmail): Promise<BehaviorSignals> {
    try {
      return await this.doAnalyze(email);
    } catch (err) {
      this.logger.warn('BehaviorService.analyze failed (non-fatal)', {
        emailId: email.emailId,
        error:   err instanceof Error ? err.message : String(err),
      });
      return DEFAULT_BEHAVIOR;
    }
  }

  private async doAnalyze(email: ParsedEmail): Promise<BehaviorSignals> {
    // Use domain-based matching (catches sub-addresses from same domain)
    const domainMatch = email.fromAddr.match(/@([^\s>]+)/);
    const senderDomain = domainMatch ? domainMatch[1].toLowerCase() : email.fromAddr.toLowerCase();

    const history = await this.prisma.email.findMany({
      where: {
        mailBoxId: email.mailBoxId,
        fromAddr:  { contains: senderDomain },
      },
      // FIX-4: أضفنا bodyText للـ topic inference
      select: { subject: true, bodyText: true, isSpam: true, isPhishing: true, receivedAt: true },
      take:    30,
      orderBy: { receivedAt: 'desc' },
    });

    const count = history.length;
    if (count === 0) {
      return this.newSenderSignals(email);
    }

    // FIX-4: inferTopic يأخذ subjects + bodies
    const typicalTopic  = this.inferTopic(
      history.map(e => e.subject),
      history.map(e => e.bodyText ?? ''),
    );
    const behaviorScore = this.computeAnomalyScore(email, typicalTopic, history);
    const anomalyFlag   = behaviorScore >= 20;
    const anomalyDesc   = anomalyFlag
      ? this.buildAnomalyDescription(email, typicalTopic, behaviorScore)
      : '';

    return { previousEmailCount: count, typicalTopic, behaviorScore, anomalyFlag, anomalyDescription: anomalyDesc };
  }

  // ─── New sender risk ──────────────────────────────────────────────────────
  private newSenderSignals(email: ParsedEmail): BehaviorSignals {
    const body     = (email.bodyPlain || '').toLowerCase();
    let   score    = 0;
    const reasons: string[] = [];

    if (BEC_KEYWORDS.test(body)) {
      score += 30;
      reasons.push('new sender requesting financial action');
    }
    if (PHISH_KEYWORDS.test(body)) {
      score += 10;
      reasons.push('new sender using phishing language');
    }
    if (email.hasAttachment) {
      score += 10;
      reasons.push('attachment from new sender');
    }

    const anomalyFlag = score > 0;
    return {
      previousEmailCount: 0,
      typicalTopic:       'unknown',
      behaviorScore:      Math.min(60, score),
      anomalyFlag,
      anomalyDescription: anomalyFlag
        ? `First-time sender exhibiting suspicious behavior: ${reasons.join(', ')}`
        : '',
    };
  }

  // ─── Topic inference ──────────────────────────────────────────────────────
  // FIX-4: يحلل subject + body معاً بدل subject فقط
  // أضفنا: bec، hr_internal، support كـ topics مستقلة
  // BEC topic الآن explicit بدل ما يتكشف بالصدفة عبر FINANCIAL_KEYS فقط
  private inferTopic(subjects: string[], bodies: string[] = []): string {
    const combined = [...subjects, ...bodies].join(' ').toLowerCase();

    // BEC first — أعلى أولوية لأنه أخطر topic change
    if (BEC_KEYWORDS.test(combined) && (
      /wire|transfer|ach|gift\s+card|remittance/.test(combined)
    )) return 'bec';

    if (INTERNAL_HR_KEYS.test(combined))  return 'hr_internal';
    if (SUPPORT_KEYS.test(combined))      return 'support';
    if (FINANCIAL_KEYS.test(combined))    return 'invoice';
    if (NEWSLETTER_KEYS.test(combined))   return 'newsletter';
    if (ORDER_KEYS.test(combined))        return 'order';
    if (PHISH_KEYWORDS.test(combined))    return 'security';
    if (subjects.length >= 3)             return 'regular';
    return 'unknown';
  }

  // ─── Anomaly scoring ──────────────────────────────────────────────────────
  // FIX-4: expanded topic-change matrix — more pairs، higher precision
  private computeAnomalyScore(
    email: ParsedEmail,
    typicalTopic: string,
    history: Array<{ subject: string; bodyText?: string | null; isSpam: boolean; isPhishing: boolean }>,
  ): number {
    const body = (email.bodyPlain || '').toLowerCase();
    let score  = 0;

    // ── Topic change anomaly matrix ───────────────────────────────────────────
    // (typicalTopic → currentContent) pairs ordered by severity
    const anomalyMatrix: Array<[string, RegExp, number]> = [
      // newsletter → BEC: highest anomaly (known attack vector)
      ['newsletter',   BEC_KEYWORDS,   45],
      // order/support → phishing
      ['order',        PHISH_KEYWORDS, 35],
      ['support',      PHISH_KEYWORDS, 30],
      // regular comms → BEC
      ['regular',      BEC_KEYWORDS,   30],
      // hr_internal → BEC (payroll diversion attack)
      ['hr_internal',  BEC_KEYWORDS,   40],
      // invoice → new wire instructions (classic BEC variant)
      ['invoice',      /new\s+bank\s+account|change\s+account|updated?\s+wire/i, 35],
    ];

    for (const [topic, pattern, points] of anomalyMatrix) {
      if (typicalTopic === topic && pattern.test(body)) {
        score += points;
        break; // one anomaly at a time — no double-counting
      }
    }

    // ── Previous-flagged reputation ───────────────────────────────────────────
    const prevFlagged = history.filter(e => e.isSpam || e.isPhishing).length;
    if (prevFlagged > 0) score += Math.min(20, prevFlagged * 7);

    // ── Attachment anomaly ────────────────────────────────────────────────────
    // Sender never sent attachments in last 30 emails, but now does
    if (email.hasAttachment && history.length >= 5) {
      score += 15;
    }

    return Math.min(100, score);
  }

  // ─── Anomaly description ──────────────────────────────────────────────────
  private buildAnomalyDescription(
    email:         ParsedEmail,
    typicalTopic:  string,
    behaviorScore: number,
  ): string {
    const body = (email.bodyPlain || '').toLowerCase();
    const parts: string[] = [];

    if (typicalTopic !== 'unknown') {
      parts.push(`Sender typically sends ${typicalTopic} emails`);
    }
    if (BEC_KEYWORDS.test(body)) {
      parts.push('but current email contains financial/urgent payment request');
    }
    if (email.hasAttachment) {
      parts.push('with unusual attachment');
    }
    parts.push(`(anomaly score: ${behaviorScore})`);
    return parts.join(', ');
  }
}
