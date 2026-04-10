export interface IpSignals {
    ipReputationScore: number | 0
    isIpBlacklisted?: boolean
    ipCountry?: string
    network?: string
    asn?: number
    asOwner?: string
    isIpDatacenter?: boolean
    isIpTor?: boolean
    isIpProxy?: boolean
    maliciousEngines?: number
    suspiciousEngines?: number
    analysisEngines?: number
    ipReports?: number
    distinctUsers?: number
    lastReportedAt?: Date
    vtReputation?: number
    hostingProvider?: string
    ipType?: "residential" | "datacenter" | "mobile"
    isScanner?: boolean
    isKnownAttacker?: boolean
}

export interface DomainSignals {
    domainReputationScore: number | 0
    domainBlacklisted?: boolean
    domainAgeDays?: number
    newlyRegisteredDomain?: boolean
    domainRegistrar?: string
    mxRecordsExist?: boolean
    historicalReputation?: number
    subdomainCount?: number
    hostingIp?: string
    sslIssuer?: string
    sslValidUntil?: Date
    lookalikeRiskScore?: number
    whoisHidden?: boolean
}

export interface ReputationSignals extends IpSignals, DomainSignals {}

