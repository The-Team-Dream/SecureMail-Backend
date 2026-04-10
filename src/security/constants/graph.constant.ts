import { RuleNode } from "../types";

export const graph: Map<string, RuleNode> = new Map([

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