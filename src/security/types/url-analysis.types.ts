export interface ParsedUrlDomain {
    hostname: string;
    domain: string;
    domainBase: string;
    publicSuffix: string;
    subdomain: string | null;
}
export interface UrlThreatSignal {
    threatScore: number;
    sources?: string[]
    isIpBased?: boolean;
    isShortened?: boolean;
    hasHomoglyphDomain?: boolean;
    isBlacklisted?: boolean;
    isSuspiciousTld?: boolean;
    isBase64Encoded?: boolean;
    hasRedirectChain?: boolean;
    verdict?: 'clean' | 'suspicious' | 'malicious' | 'unknown';
    threat?: string;
}

export interface UrlAnalysisSignals {
    totalThreatScore: number;
    analyzedUrls?: UrlThreatSignal[];
    hasHighThreatUrl?: boolean;
    hasMaliciousUrl?: boolean;
    summary?: string;
}