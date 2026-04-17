import { AttackPattern } from "src/security/types";

export const attackPatterns: AttackPattern[] = [

    {
        id: 'bec_attack',
        name: 'Business Email Compromise',
        description: 'Executive impersonation with financial pressure — no links or attachments',
        requiredRules: ['bec_language_detected'],
        optionalRules: ['reply_to_domain_mismatch',
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
