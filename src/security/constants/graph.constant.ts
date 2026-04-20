import { RuleNode } from "../types";

export const graph: Map<string, RuleNode> = new Map([
    ['email_auth_failure', {
        id: 'email_auth_failure',
        dependencies: [],
        amplifies: ['typosquatting_domain', 'homoglyph_domain_spoofing',
            'lookalike_domain_attack', 'sender_display_name_mismatch',
            'display_name_impersonation', 'reply_to_domain_mismatch'],
        amplifyFactor: 1.3,
    }],
    ['display_name_impersonation', {
        id: 'display_name_impersonation',
        dependencies: [],
        amplifies: ['bec_language_detected', 'first_contact_sender_risk',
            'reply_to_domain_mismatch'],
        amplifyFactor: 1.4,
    }],
    ['bec_language_detected', {
        id: 'bec_language_detected',
        dependencies: [],
        amplifies: ['first_contact_sender_risk', 'reply_to_domain_mismatch'],
        amplifyFactor: 1.2,
    }],
    ['newly_registered_domain', {
        id: 'newly_registered_domain',
        dependencies: [],
        amplifies: ['credential_harvesting_attempt', 'html_link_text_mismatch',
            'ip_based_url'],
        amplifyFactor: 1.3,
    }],
    // e.g. paypa1.tk + password form = PayPal phishing campaign
    ['typosquatting_domain', {
        id: 'typosquatting_domain',
        dependencies: [],
        amplifies: ['credential_harvesting_attempt', 'brand_abuse_in_body',
            'urgent_phishing_language'],
        amplifyFactor: 1.3,
    }],
    ['malicious_url_reputation', {
        id: 'malicious_url_reputation',
        dependencies: [],
        amplifies: ['html_obfuscation_phishing', 'html_link_text_mismatch',
            'base64_encoded_url'],
        amplifyFactor: 1.5,
    }],
    ['suspicious_received_headers', {
        id: 'suspicious_received_headers',
        dependencies: [],
        amplifies: ['typosquatting_domain', 'suspicious_sender_tld',
            'email_auth_failure'],
        amplifyFactor: 1.2,
    }],

]);
