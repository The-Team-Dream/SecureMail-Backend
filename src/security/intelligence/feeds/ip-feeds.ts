import { Logger } from '@nestjs/common';
import { FeedIpResult, IpSignals } from 'src/security/types';

// ─────────────────────────────────────────────────────────────
// AbuseIPDB
// ─────────────────────────────────────────────────────────────
export async function checkIpAbuseIPDB(
    ip: string,
    apiKey: string
): Promise<Partial<IpSignals> | null> {
    try {
        const res = await fetch(
            `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`,
            {
                headers: {
                    Key: apiKey,
                    Accept: "application/json",
                },
                signal: AbortSignal.timeout(5000),
            }
        );
        if (!res.ok) return null;
        const json = await res.json();
        const d = json?.data;
        return {
            ipReputationScore: d.abuseConfidenceScore,
            isIpBlacklisted: d.abuseConfidenceScore >= 25,
            ipCountry: d.countryCode,
            isIpTor: d.isTor ?? false,
            isIpDatacenter: (d.usageType ?? "").toLowerCase().includes("data center"),
            ipReports: d.totalReports,
            distinctUsers: d.numDistinctUsers,
            lastReportedAt: d.lastReportedAt
                ? new Date(d.lastReportedAt)
                : undefined,
        };
    } catch {
        return null;
    }
}


// ─────────────────────────────────────────────────────────────
// VirusTotal
// ─────────────────────────────────────────────────────────────
export async function checkIpVirusTotal(
    ip: string,
    apiKey: string
): Promise<Partial<IpSignals> | null> {
    try {
        const res = await fetch(
            `https://www.virustotal.com/api/v3/ip_addresses/${encodeURIComponent(ip)}`,
            {
                headers: {
                    "x-apikey": apiKey,
                },
                signal: AbortSignal.timeout(8000),
            }
        );
        if (!res.ok) return null;
        const json = await res.json();
        const attrs = json?.data?.attributes ?? {};
        const stats = attrs.last_analysis_stats ?? {};
        const malicious = stats.malicious ?? 0;
        const suspicious = stats.suspicious ?? 0;
        const harmless = stats.harmless ?? 0;
        const total = malicious + suspicious + harmless || 1;
        const score = Math.round(((malicious + suspicious) / total) * 100);
        return {
            ipReputationScore: score,
            isIpBlacklisted: malicious >= 5,
            maliciousEngines: malicious,
            suspiciousEngines: suspicious,
            analysisEngines: total,
            asn: attrs.asn,
            asOwner: attrs.as_owner,
            network: attrs.network,
            ipCountry: attrs.country,
            vtReputation: attrs.reputation,
        };
    } catch {
        return null;
    }
}

// ─────────────────────────────────────────────────────────────
// IP Info
// ─────────────────────────────────────────────────────────────
export async function checkIpInfo(
    ip: string,
    apiKey: string
): Promise<Partial<IpSignals> | null> {
    try {
        const res = await fetch(
            `https://ipinfo.io/${encodeURIComponent(ip)}?token=${apiKey}`,
            {
                signal: AbortSignal.timeout(5000),
            }
        );
        if (!res.ok) return null;
        const json = await res.json();
        const org = json.org ?? "";
        return {
            ipCountry: json.country,
            hostingProvider: org,
            asOwner: org,
            network: json.cidr,
            ipType: org.toLowerCase().includes("mobile")
                ? "mobile"
                : org.toLowerCase().includes("wireless")
                    ? "mobile"
                    : org.toLowerCase().includes("hosting")
                        ? "datacenter"
                        : "residential",
        };
    } catch {
        return null;
    }
}

// ─────────────────────────────────────────────────────────────
// Grey Noise
// ─────────────────────────────────────────────────────────────
export async function checkGreyNoise(
    ip: string,
    apiKey: string
): Promise<Partial<IpSignals> | null> {
    try {
        const res = await fetch(
            `https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`,
            {
                headers: {
                    key: apiKey,
                },
                signal: AbortSignal.timeout(5000),
            }
        );
        if (!res.ok) return null;
        const json = await res.json();
        return {
            isScanner: json.classification === "malicious",
            isKnownAttacker: json.noise === true,
        };
    } catch {
        return null;
    }
}



// ─────────────────────────────────────────────────────────────
// Spamhaus — DNS-based (ZEN)
// ─────────────────────────────────────────────────────────────
export async function checkIpSpamhaus(ip: string): Promise<boolean> {
    try {
        const reversed = ip.split('.').reverse().join('.');
        const { promises: dns } = await import('node:dns');
        await dns.lookup(`${reversed}.zen.spamhaus.org`);
        return true;
    } catch {
        return false;
    }
}

// ─────────────────────────────────────────────────────────────
// Fallback
// ─────────────────────────────────────────────────────────────
export function unknownIpResult(ip: string): FeedIpResult {
    return {
        ip,
        ipReputationScore: 0,
        isIpBlacklisted: false,
        isIpTor: false,
        isIpProxy: false,
    };
}
