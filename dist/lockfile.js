import { canonicalJson, prettyCanonicalJson, sha256 } from './canonical.js';
import { policyFingerprint } from './policy.js';
import { publisherFromIdentifier } from './trust.js';
export const VERSION = '0.1.0';
function lockEntry(entry, trustScore, signaturePresent) {
    const out = {
        identifier: entry.identifier,
        displayName: entry.displayName,
        type: entry.type,
        ...(typeof entry.url === 'string' ? { url: entry.url } : {}),
        ...(Object.prototype.hasOwnProperty.call(entry, 'data') ? { dataSha256: sha256(canonicalJson(entry.data)) } : {}),
        ...(typeof entry.version === 'string' ? { version: entry.version } : {}),
        ...(publisherFromIdentifier(entry.identifier) ? { publisher: publisherFromIdentifier(entry.identifier) } : {}),
        entrySha256: sha256(canonicalJson(entry)),
        trustScore,
        signaturePresent,
        capabilities: Array.isArray(entry.capabilities) ? [...entry.capabilities].sort() : [],
        tags: Array.isArray(entry.tags) ? [...entry.tags].sort() : []
    };
    return out;
}
export function createLockfile(result, policy) {
    const trustMap = new Map(result.trust.map((t) => [`${t.sourceCatalog}\0${t.identifier}`, t]));
    const catalogs = result.catalogs.map((c) => ({
        url: c.url,
        sha256: c.sha256,
        entries: c.catalog.entries
            .filter((e) => e && typeof e.identifier === 'string' && typeof e.displayName === 'string' && typeof e.type === 'string')
            .map((e) => {
            const t = trustMap.get(`${c.url}\0${e.identifier}`);
            return lockEntry(e, t?.score ?? 0, t?.signaturePresent ?? false);
        })
            .sort((a, b) => a.identifier.localeCompare(b.identifier))
    })).sort((a, b) => a.url.localeCompare(b.url));
    const graphSha256 = sha256(canonicalJson(catalogs));
    return {
        lockVersion: 1,
        generatedBy: `cataloglock@${VERSION}`,
        root: result.root,
        policySha256: policyFingerprint(policy),
        graphSha256,
        catalogs,
        findings: result.findings.map(({ ruleId, severity, message, location }) => ({ ruleId, severity, message, ...(location ? { location } : {}) }))
    };
}
export function serializeLockfile(lock) { return prettyCanonicalJson(lock); }
