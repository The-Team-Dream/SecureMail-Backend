// ─────────────────────────────────────────────────────────────────────────────
// rules/header.rules.ts
//
// Rules that inspect raw email headers.
//
// Rule 23 — Conversation Hijacking (Re: thread + financial request)
// ─────────────────────────────────────────────────────────────────────────────
// Note: Received Headers (Rule 19) and SPF/DKIM/DMARC (Rule 20) live in
// domain.rules.ts because they are tightly coupled to domain verification.
// ─────────────────────────────────────────────────────────────────────────────

import { Injectable } from '@nestjs/common';
import { EmailContentForClassification } from '../classification.service';
import { CONVERSATION_HIJACK_PATTERNS } from '../classification.constants';
import { stripHtml } from '../classification.utils';

@Injectable()
export class HeaderRules {

  check(email: EmailContentForClassification, reasons: string[]): number {
    let score = 0;

    // Rule 23 — Conversation Hijacking
    if (this.checkConversationHijacking(email)) {
      score += 35;
      reasons.push('conversation_hijacking_attempt');
    }

    return score;
  }

  // ─── Rule 23: Conversation Hijacking ────────────────────────────────────────
  /**
   * Detects financial requests injected into reply threads.
   * Attackers compromise an ongoing email thread then insert a payment request.
   *
   * Flags when BOTH conditions are true:
   *  1. Email is a reply/forward (Re:/Fwd: prefix or In-Reply-To header present)
   *  2. Body contains financial hijacking keywords
   */
  private checkConversationHijacking(email: EmailContentForClassification): boolean {
    const subject = (email.subject || '').toLowerCase().trim();

    const isReplyThread =
      subject.startsWith('re:')   ||
      subject.startsWith('fwd:')  ||
      subject.startsWith('fw:')   ||
      subject.startsWith('رد:')   ||  // Arabic reply — مهم لـ Egyptian users
      subject.startsWith('ر:')    ||  // Arabic abbreviated reply
      subject.startsWith('aw:')   ||  // German Antwort
      subject.startsWith('rép:')  ||  // French Réponse
      subject.startsWith('sv:')   ||  // Swedish/Norwegian Svar
      !!(email.headers?.['in-reply-to'] || email.headers?.['In-Reply-To']);

    if (!isReplyThread) return false;

    const body = [
      email.bodyText || '',
      stripHtml(email.bodyHtml || ''),
    ].join(' ');

    return CONVERSATION_HIJACK_PATTERNS.some(p => p.test(body));
  }
}
