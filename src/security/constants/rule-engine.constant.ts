// ─────────────────────────────────────────────────────────────────────────────
// classification.constants.ts
// All shared keyword lists, patterns, and maps used across rule files.
// ─────────────────────────────────────────────────────────────────────────────

// ─── Spam Keywords ────────────────────────────────────────────────────────────
export const SPAM_KEYWORDS = [
  'free money', 'lottery winner', 'congratulations you won', 'claim your prize',
  'act now', 'limited time offer', 'buy now',
  'crypto investment', 'bitcoin opportunity', 'nigerian prince',
  'click below',
  'dear friend', 'dear customer', 'you have been selected',
  'no purchase necessary', 'risk free', '100% free', 'guaranteed', 'cash bonus',
  'work from home', 'make money fast', 'instant approval', 'no credit check',
  'earn money', 'double your income', 'special promotion', 'exclusive offer',
  'you are a winner', 'claim now', 'prize money', 'get paid', 'passive income',
];

// ─── Phishing Urgent Patterns ─────────────────────────────────────────────────
// ✅ مُحسَّن: زيادة Arabic patterns + verify identity
export const PHISHING_URGENT_PATTERNS = [
  /\b(account\s+(suspended|locked|disabled|compromised))\b/i,
  /\b(verify\s+(your|now|immediately))\b/i,
  /\b(confirm\s+(your|now))\b/i,
  /\b(buy\s+(now))\b/i,
  /\b(urgent|immediate|asap|act now)\b/i,
  /\b(security\s+alert|suspicious\s+activity)\b/i,
  /\b(password\s+expired|reset\s+password)\b/i,
  /\b(update\s+your\s+information)\b/i,
  /\b(click\s+here\s+to\s+(verify|confirm|update))\b/i,
  /\b(verify\s+identity|confirm\s+identity)\b/i,           // ✅ مضاف
  /\b(unauthorized\s+access|someone\s+tried)\b/i,
  /\b(limited\s+time|expires\s+soon|within\s+\d+\s*hours?)\b/i,
  // Arabic patterns — Egyptian market
  /(حسابك\s+(معلق|مغلق|موقوف|محظور))/u,
  /(نشاط\s+مشبوه|محاولة\s+(دخول|تسجيل)\s+غير\s+مصرحة?)/u,
  /(تحديث\s+بياناتك|تأكيد\s+هويتك|التحقق\s+من\s+حسابك)/u,  // ✅ مضاف
  /(انتهت\s+صلاحية|تجديد\s+(كلمة\s+المرور|الحساب))/u,       // ✅ مضاف
  /(اضغط\s+هنا|انقر\s+هنا)\s+(للتحقق|للتأكيد|للتحديث)/u,   // ✅ مضاف
  /(تحقق\s+من\s+هويتك|أدخل\s+بياناتك|حسابك\s+في\s+خطر)/u,  // ✅ مضاف
];

// ─── BEC Patterns ─────────────────────────────────────────────────────────────
// ✅ مُحسَّن: زيادة vendor change + invoice patterns
export const BEC_PATTERNS = [
  /\b(urgent\s+payment|wire\s+transfer|bank\s+transfer)\b/i,
  /\b(gift\s+card[s]?|itunes|google\s+play\s+card)\b/i,
  /\b(confidential\s+(request|matter))\b/i,
  /\b(handle\s+this\s+(quickly|immediately|urgently))\b/i,
  /\b(don['`]?t\s+(tell|mention|discuss)\s+(anyone|others))\b/i,
  /\b(keep\s+this\s+(private|confidential|between\s+us))\b/i,
  /\b(ceo|president|director|executive)\s+(request|approval|authorization)\b/i,
  /\b(process\s+this\s+payment|approve\s+this\s+transfer)\b/i,
  /\b(vendor\s+change|supplier\s+update|new\s+bank\s+account)\b/i,  // ✅ مضاف
  /\b(invoice\s+(attached|enclosed|pending|overdue))\b/i,            // ✅ مضاف
];

// ─── Conversation Hijacking Patterns ──────────────────────────────────────────
export const CONVERSATION_HIJACK_PATTERNS = [
  /\b(wire\s+transfer|bank\s+transfer)\b/i,
  /\b(update\s+(payment|banking)\s+details?)\b/i,
  /\b(new\s+bank\s+account|change\s+(of\s+)?account)\b/i,
  /\b(urgent\s+payment|payment\s+required)\b/i,
  /\b(updated?\s+(invoice|billing)\s+info(rmation)?)\b/i,
];

// ─── Shortened URL Domains ────────────────────────────────────────────────────
export const SHORTENED_URL_DOMAINS = [
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly',
  'adf.ly', 'j.mp', 'tr.im', 'cutt.ly', 'shorturl', 'rebrand.ly',
];

// ─── Temp / Disposable Sender Domains ────────────────────────────────────────
export const SUSPICIOUS_SENDER_DOMAINS = [
  'tempmail', 'throwaway', 'guerrillamail', '10minutemail', 'mailinator',
  'fakeinbox', 'trashmail', 'yopmail', 'dispostable', 'sharklasers',
  'getairmail', 'spamgourmet', 'mytrashmail', 'mailnull',
  'temp-mail', 'maildrop', 'mailnesia', 'minuteinbox',
  'tempinbox', 'dropmail', 'burnermail', 'emailondeck', 'discard',
];

// ─── Suspicious TLDs ──────────────────────────────────────────────────────────
export const SUSPICIOUS_TLDS = new Set([
  'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work',
  'click', 'link', 'download', 'loan', 'win', 'racing',
]);

// ─── Risky Attachment Extensions ─────────────────────────────────────────────
export const RISKY_ATTACHMENT_EXTENSIONS = [
  '.exe', '.bat', '.cmd', '.scr', '.pif', '.vbs', '.vbe', '.js',
  '.jse', '.wsf', '.wsh', '.msi', '.jar', '.com', '.lnk',
  '.xlsm', '.xlsb', '.docm', '.pptm', '.xltm', '.dotm', '.ps1',
  '.psm1', '.hta', '.reg', '.inf',
  '.zip', '.rar', '.7z', '.gz', '.tar',
  '.iso', '.img',
];

// ─── Financial Attachment Keywords ───────────────────────────────────────────
export const FINANCIAL_ATTACHMENT_KEYWORDS = [
  'invoice', 'payment', 'receipt', 'statement', 'transfer',
  'bank', 'wire', 'swift', 'iban', 'account',
];

// ─── Sensitive Role Keywords (Display Name Impersonation) ────────────────────
// ✅ مُحسَّن: phrases كاملة بدل كلمات منفردة لتجنب false positives
export const SENSITIVE_ROLE_KEYWORDS = [
  // C-Suite — standalone word boundary
  'ceo', 'cfo', 'coo', 'cto', 'president', 'director',
  'vp',
  // Role phrases — require full phrase
  'finance department', 'accounting department', 'payroll department',
  'it support', 'helpdesk', 'help desk',
  'system admin', 'sysadmin', 'security team',
  'hr department', 'human resources', 'legal department',
  // Arabic roles — Egyptian market
  'نائب الرئيس', 'المدير التنفيذي', 'الرئيس التنفيذي',
];

// ─── Lookalike Phishing Keywords (in domain) ─────────────────────────────────
export const LOOKALIKE_PHISHING_KEYWORDS = [
  'secure', 'login', 'verify', 'account', 'update', 'support',
  'confirm', 'signin', 'sign-in', 'banking', 'portal', 'auth',
  'authentication', 'validation', 'recovery', 'alert', 'notice',
];

// ─── Arabic Brand Aliases — Egyptian market ───────────────────────────────────
export const ARABIC_BRAND_ALIASES: Map<string, string[]> = new Map([
  ['fawry',      ['فوري',     'فورى']],
  ['instapay',   ['إنستاباي', 'انستاباي', 'إنستا باي']],
  ['meeza',      ['ميزة',     'ميزه']],
  ['cib',        ['سي اي بي', 'بنك CIB']],
  ['nbe',        ['البنك الأهلي', 'الأهلي المصري']],
  ['vodafone',   ['فودافون',  'فودا فون']],
  ['orange',     ['أورانج']],
]);

// ─── English Brand Aliases ────────────────────────────────────────────────────
export const ENGLISH_BRAND_ALIASES: Map<string, string[]> = new Map([
  ['paypal',     ['paypal']],
  ['google',     ['google', 'gmail', 'youtube', 'googlemail']],
  ['microsoft',  ['microsoft', 'outlook', 'live', 'hotmail', 'office', 'msn']],
  ['apple',      ['apple', 'icloud']],
  ['amazon',     ['amazon', 'aws', 'amazonses']],
  ['netflix',    ['netflix']],
  ['facebook',   ['facebook', 'fb', 'meta', 'instagram', 'whatsapp']],
  ['instagram',  ['instagram', 'fb', 'meta']],
  ['twitter',    ['twitter', 'x']],
  ['linkedin',   ['linkedin']],
  ['github',     ['github', 'githubusercontent']],
  ['dropbox',    ['dropbox']],
  ['stripe',     ['stripe']],
  ['shopify',    ['shopify', 'myshopify']],
  ['zoom',       ['zoom', 'zoomgov']],
  ['slack',      ['slack']],
  ['adobe',      ['adobe']],
  ['spotify',    ['spotify']],
  ['uber',       ['uber']],
  ['airbnb',     ['airbnb']],
  ['binance',    ['binance']],
  ['coinbase',   ['coinbase']],
  ['ebay',       ['ebay']],
  ['alibaba',    ['alibaba', 'aliexpress', 'taobao']],
  ['tiktok',     ['tiktok', 'bytedance']],
  ['samsung',    ['samsung']],
  ['vodafone',   ['vodafone']],
  ['orange',     ['orange']],
  ['etisalat',   ['etisalat', 'eand']],
  ['tedata',     ['tedata']],
  ['cib',        ['cib', 'cibeg']],
  ['nbe',        ['nbe', 'nbe-eg']],
  ['alexbank',   ['alexbank']],
  ['banque',     ['banquemisr']],
  ['qnb',        ['qnb', 'qnbalahli']],
  ['hsbc',       ['hsbc']],
  ['fawry',      ['fawry']],
  ['instapay',   ['instapay']],
  ['meeza',      ['meeza']],
  ['aman',       ['aman', 'amanpay']],
  ['masary',     ['masary']],
  ['valu',       ['valu']],
]);

// ─── Brand Map 
export const BRAND_MAP = new Map<string, string[]>([
  ...ARABIC_BRAND_ALIASES,
  ...ENGLISH_BRAND_ALIASES,
]);

// ─── Brand Reverse Index — O(1) lookup ────────────────────────────────────────
export const BRAND_REVERSE_INDEX = new Map<string, string>(
  [...BRAND_MAP.entries()].flatMap(([brand, bases]) =>
    bases.map(base => [base, brand] as [string, string])
  )
);

// ─── Trusted Sending Services ─────────────────────────────────────────────────
export const TRUSTED_SENDING_SERVICES = [
  'mailchimp', 'sendgrid', 'klaviyo', 'hubspot', 'salesforce',
  'mailgun', 'constantcontact', 'campaign-monitor', 'brevo',
  'sendinblue', 'aweber', 'getresponse', 'activecampaign',
  'amazonses', 'postmarkapp', 'sparkpost', 'paypal',
  'typeform', 'formspree', 'jotform', 'wufoo', 'cognito',
];

// ─── Homoglyph Map ────────────────────────────────────────────────────────────
export const HOMOGLYPH_MAP: Record<string, string> = {
  // Cyrillic → Latin
  '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
  '\u0441': 'c', '\u0445': 'x', '\u0456': 'i', '\u0458': 'j',
  '\u0443': 'y',
  // Greek → Latin
  '\u03BF': 'o', '\u03B1': 'a', '\u03C1': 'p',
  '\u03B2': 'b', '\u03B7': 'n', '\u03C4': 't',
  '\u03BD': 'v', '\u03BA': 'k', '\u03C9': 'w',
  // Latin lookalikes
  '\u0501': 'd', '\u0261': 'g', '\u0131': 'i', '\u013a': 'l',
};

// ─── Known Good Domains Whitelist ─────────────────────────────────────────────
export const WHITELISTED_DOMAINS = new Set([
  'github.com', 'gitlab.com', 'stackoverflow.com',
  'google.com', 'gmail.com', 'googlemail.com',
  'microsoft.com', 'outlook.com', 'live.com', 'hotmail.com',
  'apple.com', 'icloud.com',
  'amazon.com', 'aws.amazon.com',
  'linkedin.com', 'twitter.com', 'x.com',
  'paypal.com', 'stripe.com',
  'zoom.com', 'zoom.us', 'slack.com',
  'me.com', 't.co',
  'yahoo.com', 'yahoo.co.uk', 'yahoo.com.eg', 'yahoo.fr', 'yahoo.de',
  'proton.me', 'protonmail.com', 'protonmail.ch',
  'typeform.com', 'formspree.io', 'jotform.com', 'wufoo.com',
  'shopify.com', 'hubspot.com', 'dropbox.com', 'notion.so',
  'fawry.com', 'instapay.com.eg',
  'nbe.com.eg', 'cib.com.eg', 'banquemisr.com',
  'yourcompany.com',
]);

// ─── Rule Weights ─────────────────────────────────────────────────────────────
export const RULE_WEIGHTS: Record<string, { score: number; minCorroboration: number }> = {
  spam_keywords_detected:         { score: 5,  minCorroboration: 0 },
  disposable_sender_domain:       { score: 15, minCorroboration: 0 },
  excessive_capitalization:       { score: 5,  minCorroboration: 0 },
  excessive_exclamation_marks:    { score: 5,  minCorroboration: 0 },
  excessive_links:                { score: 5,  minCorroboration: 0 },
  bec_language_detected:          { score: 10, minCorroboration: 0 },
  risky_attachment_detected:      { score: 20, minCorroboration: 0 },
  sender_display_name_mismatch:   { score: 15, minCorroboration: 1 },
  urgent_phishing_language:       { score: 10, minCorroboration: 0 },
  ip_based_url:                   { score: 15, minCorroboration: 0 },
  shortened_url:                  { score: 15, minCorroboration: 0 },
  suspicious_sender_tld:          { score: 10, minCorroboration: 0 },
  html_link_text_mismatch:        { score: 30, minCorroboration: 1 },
  first_contact_sender_risk:      { score: 10, minCorroboration: 0 },
  brand_abuse_in_body:            { score: 20, minCorroboration: 1 },
  homoglyph_domain_spoofing:      { score: 30, minCorroboration: 0 },
  reply_to_domain_mismatch:       { score: 20, minCorroboration: 1 },
  suspicious_received_headers:    { score: 25, minCorroboration: 1 },
  email_auth_failure:             { score: 15, minCorroboration: 0 },
  display_name_impersonation:     { score: 30, minCorroboration: 1 },
  credential_harvesting_attempt:  { score: 50, minCorroboration: 0 },
  conversation_hijacking_attempt: { score: 35, minCorroboration: 1 },
  lookalike_domain_attack:        { score: 30, minCorroboration: 1 },
  html_obfuscation_phishing:      { score: 25, minCorroboration: 1 },
  base64_encoded_url:             { score: 40, minCorroboration: 1 },
  typosquatting_domain:           { score: 35, minCorroboration: 0 },
  newly_registered_domain:        { score: 15, minCorroboration: 0 },
  malicious_url_reputation:       { score: 50, minCorroboration: 0 },
};

// ─── Phishing Rule IDs ────────────────────────────────────────────────────────
export const PHISHING_RULE_IDS = new Set([
  'sender_display_name_mismatch', 'urgent_phishing_language',
  'ip_based_url', 'shortened_url', 'suspicious_sender_tld',
  'html_link_text_mismatch', 'first_contact_sender_risk',
  'brand_abuse_in_body', 'homoglyph_domain_spoofing',
  'reply_to_domain_mismatch', 'suspicious_received_headers',
  'email_auth_failure', 'display_name_impersonation',
  'credential_harvesting_attempt', 'conversation_hijacking_attempt',
  'lookalike_domain_attack', 'html_obfuscation_phishing',
  'base64_encoded_url', 'typosquatting_domain',
  'newly_registered_domain', 'malicious_url_reputation',
]);

// ─── Rule Descriptions ────────────────────────────────────────────────────────
export const RULE_DESCRIPTIONS: Record<string, string> = {
  spam_keywords_detected:         'Email contains known spam keywords or fuzzy variants',
  disposable_sender_domain:       'Sender is using a temporary or disposable email domain',
  excessive_capitalization:       'More than 50% of text is in UPPERCASE',
  excessive_exclamation_marks:    'More than 3 exclamation marks detected',
  excessive_links:                'Email contains more than 5 hyperlinks',
  typosquatting_domain:           'Sender domain closely resembles a known brand (typosquatting)',
  sender_display_name_mismatch:   'Display name claims to be a known brand but domain does not match',
  urgent_phishing_language:       'Email uses urgent or threatening language to pressure the recipient',
  ip_based_url:                   'Email contains a URL with a raw IP address instead of a domain',
  shortened_url:                  'Email contains a shortened URL that hides the real destination',
  suspicious_sender_tld:          'Sender domain uses a high-risk TLD (.tk, .ml, .xyz, etc.)',
  html_link_text_mismatch:        'Link text shows one domain but the actual href points elsewhere',
  first_contact_sender_risk:      'First time this sender has contacted this mailbox',
  bec_language_detected:          'Email contains Business Email Compromise language patterns',
  risky_attachment_detected:      'Email has a risky attachment type or office file with financial keywords',
  brand_abuse_in_body:            'A known brand is mentioned with phishing action words but sender is unrelated',
  homoglyph_domain_spoofing:      'Sender domain uses lookalike Unicode characters to impersonate a brand',
  reply_to_domain_mismatch:       'Reply-To address points to a different domain than the From address',
  suspicious_received_headers:    'Email claims to be from a known brand but mail servers do not match',
  email_auth_failure:             'SPF, DKIM, or DMARC authentication failed or is missing',
  display_name_impersonation:     'Display name contains a sensitive role (CEO, IT Support, HR) from unofficial domain',
  credential_harvesting_attempt:  'Email HTML contains a form or password input to steal credentials',
  conversation_hijacking_attempt: 'A reply thread has been hijacked with a financial request',
  lookalike_domain_attack:        'Sender domain combines a brand name with phishing keywords',
  html_obfuscation_phishing:      'Email uses HTML tricks to evade filters',
  base64_encoded_url:             'A URL or phishing content is hidden inside a Base64-encoded string',
  newly_registered_domain:        'Sender domain was registered recently (high risk for phishing)',
  malicious_url_reputation:       'A URL in the email was found in a threat intelligence blacklist',
};