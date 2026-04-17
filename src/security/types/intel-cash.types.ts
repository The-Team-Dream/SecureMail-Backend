import { DomainSignals, IpSignals } from 'src/security/types/repu.types';
import { UrlThreatSignal } from 'src/security/types/url-analysis.types';

export interface UrlIntelResult extends UrlThreatSignal {
    url: string;
    source: 'cache' | 'local' | 'grpc';
    cachedAt: number;
    // UrlThreatSignal already has: threatScore, verdict, threat, sources, isBlacklisted...
}

export interface IpIntelResult extends IpSignals {
    ip: string;
    source: 'cache' | 'local';
    cachedAt: number;
    // IpSignals already has: ipReputationScore, isIpBlacklisted, ipCountry, isIpDatacenter, isIpTor, isIpProxy...
}

export interface DomainIntelResult extends DomainSignals {
    domain: string;
    source: 'cache' | 'local';
    cachedAt: number;
    // DomainSignals already has: domainReputationScore, domainBlacklisted, domainAgeDays, newlyRegisteredDomain...
}
