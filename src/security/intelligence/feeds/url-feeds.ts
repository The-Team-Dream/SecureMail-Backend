export async function checkUrlVirusTotal(
    url: string,
    apiKey: string
) {
    if (!apiKey) return null
    const encoded = Buffer.from(url).toString('base64url')
    const res = await fetch(
        `https://www.virustotal.com/api/v3/urls/${encoded}`,
        {
            headers: { 'x-apikey': apiKey }
        }
    )
    if (!res.ok) return null
    const data = await res.json()
    const stats = data.data?.attributes?.last_analysis_stats ?? {}
    const malicious = stats.malicious ?? 0
    const suspicious = stats.suspicious ?? 0
    if (malicious > 0 || suspicious > 0) {
        return {
            isBlacklisted: true,
            score: Math.min(100, malicious * 20 + suspicious * 10),
            threat: 'malware/phishing'
        }
    }
    return {
        isBlacklisted: false,
        score: 0
    }
}



export async function checkUrlPhishTank(
    url: string,
    apiKey: string
) {
    if (!apiKey) return null
    const res = await fetch(
        `https://checkurl.phishtank.com/checkurl/`,
        {
            method: 'POST',
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded'
            },
            body: `url=${encodeURIComponent(url)}&format=json`
        }
    )
    if (!res.ok) return null
    const data = await res.json()
    if (data.results?.in_database && data.results?.verified) {
        return {
            isBlacklisted: true,
            score: 90,
            threat: 'phishing'
        }
    }
    return {
        isBlacklisted: false,
        score: 0
    }
}



export async function checkUrlScan(
    url: string,
    apiKey: string
) {
    if (!apiKey) return null
    const res = await fetch(
        `https://urlscan.io/api/v1/search/?q=page.url:${encodeURIComponent(url)}`,
        {
            headers: { 'API-Key': apiKey }
        }
    )
    if (!res.ok) return null
    const data = await res.json()
    if (data.total > 0) {
        const malicious = data.results.some(
            (r: any) => r.verdicts?.overall?.malicious
        )
        if (malicious) {
            return {
                isBlacklisted: true,
                score: 85,
                threat: 'malicious website'
            }
        }
    }
    return {
        isBlacklisted: false,
        score: 0
    }
}
