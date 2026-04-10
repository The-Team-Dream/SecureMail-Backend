import { DomainIntelResult, IpIntelResult, UrlIntelResult } from 'src/security/types/intel-cash.types';
import { DomainSignals, IpSignals } from 'src/security/types/repu.types';
import { UrlThreatSignal } from 'src/security/types/url-analysis.types';
export interface FeedIpResult extends IpSignals {
    ip: string;
}

export interface FeedDomainResult extends DomainSignals {
    domain: string;
}

export interface FeedUrlResult extends UrlThreatSignal {
    url: string;
    isBlacklisted: boolean; 
    sources?: string[];  
}

export interface ThreatFeedsConfig {
    abuseIpDbKey: string;
    virusTotalKey: string;
    urlScanKey: string;
    phishTankKey: string;
    ipinfoKey: string;
    greynoiseKey: string;
}