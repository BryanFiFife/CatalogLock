export function publisherFromIdentifier(identifier) {
    const m = identifier.match(/^urn:air:([^:]+):[^:]+:.+$/i);
    return m?.[1]?.toLowerCase();
}
export function hostWithin(host, publisher) {
    const h = host.toLowerCase().replace(/\.$/, '');
    const p = publisher.toLowerCase().replace(/\.$/, '');
    return h === p || h.endsWith(`.${p}`);
}
export function identityHost(identity) {
    try {
        if (identity.startsWith('did:web:')) {
            const rest = identity.slice('did:web:'.length);
            const first = rest.split(':')[0];
            if (!first)
                return undefined;
            const decoded = decodeURIComponent(first).toLowerCase();
            return decoded.startsWith('[') ? new URL(`https://${decoded}`).hostname.toLowerCase() : decoded.split(':')[0];
        }
        if (identity.startsWith('spiffe://') || identity.startsWith('https://'))
            return new URL(identity).hostname.toLowerCase();
    }
    catch {
        return undefined;
    }
    return undefined;
}
function attestationNames(manifest) {
    if (!Array.isArray(manifest?.attestations))
        return [];
    return manifest.attestations.map((a) => typeof a?.type === 'string' ? a.type : '').filter(Boolean).sort();
}
export function assessHostTrust(catalog, sourceCatalog) {
    const findings = [];
    const sourceHost = new URL(sourceCatalog).hostname.toLowerCase();
    const identity = typeof catalog.host?.trustManifest?.identity === 'string' ? catalog.host.trustManifest.identity : undefined;
    if (identity) {
        const host = identityHost(identity);
        if (!host || !hostWithin(host, sourceHost)) {
            findings.push({
                ruleId: 'authority/host-trust-identity',
                severity: 'critical',
                message: `Host trust identity does not align with catalog source ${sourceHost}`,
                location: sourceCatalog,
                evidence: { identity }
            });
        }
    }
    return findings;
}
export function assessEntryTrust(entry, sourceCatalog, requirePublisherMatch = true) {
    const findings = [];
    const sourceHost = new URL(sourceCatalog).hostname.toLowerCase();
    const publisher = publisherFromIdentifier(entry.identifier);
    const publisherMatchesSource = !!publisher && hostWithin(sourceHost, publisher);
    if (!publisher)
        findings.push({ ruleId: 'authority/identifier', severity: 'error', message: `Identifier is not a domain-anchored urn:air value: ${entry.identifier}`, location: sourceCatalog });
    else if (!publisherMatchesSource && requirePublisherMatch)
        findings.push({ ruleId: 'authority/publisher-source', severity: 'critical', message: `Identifier publisher ${publisher} does not control source host ${sourceHost}`, location: sourceCatalog, evidence: { identifier: entry.identifier } });
    let entryUrlHost;
    let entryUrlWithinPublisher = true;
    if (entry.url) {
        try {
            entryUrlHost = new URL(entry.url).hostname.toLowerCase();
            if (publisher)
                entryUrlWithinPublisher = hostWithin(entryUrlHost, publisher);
            if (publisher && !entryUrlWithinPublisher)
                findings.push({ ruleId: 'authority/resource-host', severity: 'warning', message: `Resource URL host ${entryUrlHost} is outside publisher authority ${publisher}`, location: entry.url });
        }
        catch {
            entryUrlWithinPublisher = false;
        }
    }
    const identity = typeof entry.trustManifest?.identity === 'string' ? entry.trustManifest.identity : undefined;
    let identityMatchesPublisher;
    if (identity && publisher) {
        const host = identityHost(identity);
        identityMatchesPublisher = !!host && hostWithin(host, publisher);
        if (!identityMatchesPublisher)
            findings.push({ ruleId: 'authority/trust-identity', severity: 'critical', message: `Trust identity does not align with publisher ${publisher}`, location: sourceCatalog, evidence: { identity, identifier: entry.identifier } });
    }
    const signaturePresent = entry.trustManifest?.signature !== undefined;
    const attestations = attestationNames(entry.trustManifest);
    let score = 0;
    if (publisherMatchesSource)
        score += 50;
    if (entryUrlWithinPublisher)
        score += 20;
    if (identityMatchesPublisher === true)
        score += 30;
    const assessment = {
        identifier: entry.identifier,
        sourceCatalog,
        ...(publisher ? { publisher } : {}),
        publisherMatchesSource,
        ...(entryUrlHost ? { entryUrlHost } : {}),
        entryUrlWithinPublisher,
        ...(identity ? { identity } : {}),
        ...(identityMatchesPublisher !== undefined ? { identityMatchesPublisher } : {}),
        signaturePresent,
        attestations,
        score
    };
    return { assessment, findings };
}
