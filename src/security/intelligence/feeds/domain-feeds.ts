import whois from 'whois-json';
import { DomainSignals } from "src/security/types";

// ─────────────────────────────────────────────────────────────
// Virus Total
// ─────────────────────────────────────────────────────────────
export async function checkDomainVirusTotal(domain: string, apiKey: string): Promise<Partial<DomainSignals> | null> {
    try {
        const res = await fetch(`https://www.virustotal.com/api/v3/domains/${encodeURIComponent(domain)}`, {
            headers: { "x-apikey": apiKey },
            signal: AbortSignal.timeout(8000),
        });
        if (!res.ok) return null;
        const json = await res.json();
        const attrs = json?.data?.attributes ?? {};
        return {
            domainReputationScore: attrs.reputation,
            domainBlacklisted: attrs.last_analysis_stats?.malicious > 0,
            hostingIp: attrs.last_https_certificate?.ip_address,
            sslIssuer: attrs.last_https_certificate?.issuer_name,
            sslValidUntil: attrs.last_https_certificate?.valid_to
                ? new Date(attrs.last_https_certificate.valid_to * 1000)
                : undefined,
        };
    } catch {
        return null;
    }
}

// ─────────────────────────────────────────────────────────────
// Abuse IPDB
// ─────────────────────────────────────────────────────────────
export async function checkDomainAbuseIPDB(domain: string, apiKey: string): Promise<Partial<DomainSignals> | null> {
    try {
        const res = await fetch(
            `https://api.abuseipdb.com/api/v2/check-domain?domain=${encodeURIComponent(domain)}`,
            {
                headers: { Key: apiKey, Accept: "application/json" },
                signal: AbortSignal.timeout(5000),
            }
        );
        if (!res.ok) return null;
        const json = await res.json();
        const d = json?.data;
        return {
            domainBlacklisted: d.totalReports > 0,
            domainReputationScore: d.abuseConfidenceScore,
        };
    } catch {
        return null;
    }
}

// ─────────────────────────────────────────────────────────────
// Whois
// ─────────────────────────────────────────────────────────────
export async function checkDomainWhois(domain: string): Promise<Partial<DomainSignals> | null> {
    try {
        const data = await whois(domain);
        const creationDate = data.creationDate ? new Date(data.creationDate) : undefined;
        if (!creationDate) {
            return {
                domainRegistrar: data.registrar ?? undefined,
                whoisHidden: !data.registrant,
            };
        }
        const ageDays = Math.floor(
            (Date.now() - creationDate.getTime()) / (1000 * 60 * 60 * 24)
        );
        return {
            domainRegistrar: data.registrar ?? undefined,
            domainAgeDays: ageDays,
            newlyRegisteredDomain: ageDays < 30,
            whoisHidden: !data.registrant,
        };
    } catch {
        return null;
    }
}
