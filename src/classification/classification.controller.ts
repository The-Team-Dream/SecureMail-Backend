import {
  Controller, Post, Body, UseGuards, HttpCode, HttpStatus,
} from '@nestjs/common';
import { Throttle, ThrottlerGuard } from '@nestjs/throttler';
import { ClassificationService } from './classification.service';
import { ClassifyEmailDto, ClassifyBatchDto } from './dto/classify-email.dto';
import { TokenGuard } from '../auth/guards/auth.guard';

@UseGuards(TokenGuard)
@Controller('classification')
export class ClassificationController {
  constructor(private readonly classificationService: ClassificationService) {}

  // ─── Endpoint 1: Classify a single email ─────────────────────────────────
  // POST /classification/classify
  //
  // Body: ClassifyEmailDto
  //
  // Response:
  // {
  //   isSpam: boolean,
  //   isPhishing: boolean,
  //   spamScore: number,      // 0-100
  //   phishingScore: number,  // 0-100
  //   reasons: string[]       // list of triggered rule names
  // }
  @Post('classify')
  @HttpCode(HttpStatus.OK)
  async classify(@Body() dto: ClassifyEmailDto) {
    const result = await this.classificationService.classify(dto);
    return {
      isSpam:        result.isSpam,
      isPhishing:    result.isPhishing,
      spamScore:     result.spamScore,
      phishingScore: result.phishingScore,
      reasons:       result.reasons,
      ruleHits:      result.ruleHits,
    };
  }

  // ─── Endpoint 2: Classify a batch of emails ───────────────────────────────
  // POST /classification/classify/batch
  //
  // Body: { emails: ClassifyEmailDto[] }
  //
  // Response:
  // {
  //   total: number,
  //   results: [
  //     {
  //       index: number,        // position in input array
  //       subject: string,
  //       fromAddr: string,
  //       isSpam: boolean,
  //       isPhishing: boolean,
  //       spamScore: number,
  //       phishingScore: number,
  //       reasons: string[]
  //     }
  //   ],
  //   summary: {
  //     spam: number,
  //     phishing: number,
  //     safe: number
  //   }
  // }
  // BUG-10 FIX (v14): rate limiting on batch endpoint
  // 100 emails × Rule 13 Prisma query × unlimited parallel requests = DB flood
  // @Throttle: max 10 batch requests per minute per IP
  // Note: ThrottlerModule must be imported in ClassificationModule (or AppModule)
  @Throttle({ default: { limit: 10, ttl: 60000 } })
  @Post('classify/batch')
  @HttpCode(HttpStatus.OK)
  async classifyBatch(@Body() dto: ClassifyBatchDto) {
    const results = await Promise.all(
      dto.emails.map((email, index) =>
        this.classificationService.classify(email).then(result => ({
          index,
          subject:       email.subject,
          fromAddr:      email.fromAddr,
          isSpam:        result.isSpam,
          isPhishing:    result.isPhishing,
          spamScore:     result.spamScore,
          phishingScore: result.phishingScore,
          reasons:       result.reasons,
          ruleHits:      result.ruleHits,
        })),
      ),
    );

    const summary = results.reduce(
      (acc, r) => {
        if (r.isPhishing) acc.phishing++;
        else if (r.isSpam) acc.spam++;
        else acc.safe++;
        return acc;
      },
      { spam: 0, phishing: 0, safe: 0 },
    );

    return { total: results.length, results, summary };
  }

  // ─── Endpoint 3: Debug — returns full rule-by-rule breakdown ─────────────
  // POST /classification/classify/debug
  //
  // Same body as /classify but response includes a detailed score breakdown
  // showing which rule group contributed how much to the final score.
  //
  // Response:
  // {
  //   isSpam: boolean,
  //   isPhishing: boolean,
  //   spamScore: number,
  //   phishingScore: number,
  //   reasons: string[],
  //   verdict: "spam" | "phishing" | "spam_and_phishing" | "safe",
  //   debug: {
  //     thresholds: { spam: 40, phishing: 30 },
  //     triggeredRules: number,
  //     ruleBreakdown: { rule: string, triggered: boolean }[]
  //   }
  // }
  @Post('classify/debug')
  @HttpCode(HttpStatus.OK)
  async classifyDebug(@Body() dto: ClassifyEmailDto) {
    const result = await this.classificationService.classify(dto);

    const allRules = [
      'spam_keywords_detected',
      'disposable_sender_domain',
      'excessive_capitalization',
      'excessive_exclamation_marks',
      'excessive_links',
      'typosquatting_domain',
      'sender_display_name_mismatch',
      'urgent_phishing_language',
      'ip_based_url',
      'shortened_url',
      'suspicious_sender_tld',
      'html_link_text_mismatch',
      'first_contact_sender_risk',
      'bec_language_detected',
      'risky_attachment_detected',
      'brand_abuse_in_body',
      'homoglyph_domain_spoofing',
      'reply_to_domain_mismatch',
      'suspicious_received_headers',
      'email_auth_failure',
      'display_name_impersonation',
      'credential_harvesting_attempt',
      'conversation_hijacking_attempt',
      'lookalike_domain_attack',
      'html_obfuscation_phishing',
      'base64_encoded_url',
      'newly_registered_domain', // Rule 27 — STUB, not active yet
    ];

    let verdict: string;
    if (result.isSpam && result.isPhishing) verdict = 'spam_and_phishing';
    else if (result.isPhishing)             verdict = 'phishing';
    else if (result.isSpam)                 verdict = 'spam';
    else                                    verdict = 'safe';

    return {
      isSpam:        result.isSpam,
      isPhishing:    result.isPhishing,
      spamScore:     result.spamScore,
      phishingScore: result.phishingScore,
      reasons:       result.reasons,
      ruleHits:      result.ruleHits,
      verdict,
      debug: {
        thresholds:     { spam: 40, phishing: 30 },
        triggeredRules: result.reasons.length,
        ruleBreakdown:  allRules.map(rule => ({
          rule,
          triggered: result.reasons.includes(rule),
        })),
      },
    };
  }
}
