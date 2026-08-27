import { canonicalJson, prettyCanonicalJson, sha256 } from './canonical.js';
import { policyFingerprint } from './policy.js';
import { publisherFromIdentifier } from './trust.js';
import type { CatalogLockfile, LockedCatalog, LockedEntry, Policy, ResolveResult, TrustAssessment } from './types.js';

export const VERSION = '0.3.0';

function lockEntry(entry: ResolveResult['catalogs'][number]['catalog']['entries'][number], trust?: TrustAssessment): LockedEntry {
  return {
    identifier: entry.identifier,
    displayName: entry.displayName,
    type: entry.type,
    ...(typeof entry.url === 'string' ? { url: entry.url } : {}),
    ...(Object.prototype.hasOwnProperty.call(entry, 'data') ? { dataSha256: sha256(canonicalJson(entry.data)) } : {}),
    ...(typeof entry.version === 'string' ? { version: entry.version } : {}),
    ...(publisherFromIdentifier(entry.identifier) ? { publisher: publisherFromIdentifier(entry.identifier)! } : {}),
    entrySha256: sha256(canonicalJson(entry)),
    trustScore: trust?.score ?? 0,
    trustState: trust?.state ?? 'absent',
    ...(trust?.trustEvidenceSha256 ? { trustEvidenceSha256: trust.trustEvidenceSha256 } : {}),
    signaturePresent: trust?.signaturePresent ?? false,
    capabilities: Array.isArray(entry.capabilities) ? [...entry.capabilities].sort() : [],
    tags: Array.isArray(entry.tags) ? [...entry.tags].sort() : []
  };
}

export function createLockfile(result: ResolveResult & { mcpSurfaces?: CatalogLockfile['mcpSurfaces'] }, policy: Policy): CatalogLockfile {
  const trustMap = new Map(result.trust.map(t => [`${t.sourceCatalog}\0${t.identifier}`, t]));
  const catalogs: LockedCatalog[] = result.catalogs.map(c => ({
    url: c.url,
    sha256: c.sha256,
    entries: c.catalog.entries
      .filter(e => e && typeof e.identifier === 'string' && typeof e.displayName === 'string' && typeof e.type === 'string')
      .map(e => lockEntry(e, trustMap.get(`${c.url}\0${e.identifier}`)))
      .sort((a,b) => a.identifier.localeCompare(b.identifier))
  })).sort((a,b) => a.url.localeCompare(b.url));

  const mcpSurfaces = [...(result.mcpSurfaces ?? [])].sort((a,b) => a.surfaceId.localeCompare(b.surfaceId));
  const graphSha256 = sha256(canonicalJson({
    root: result.root,
    rootSourceKind: result.rootSourceKind,
    ardContextSha256: result.ardContextSha256,
    catalogs,
    mcpSurfaces
  }));
  return {
    lockVersion: 3,
    generatedBy: `cataloglock@${VERSION}`,
    root: result.root,
    rootSourceKind: result.rootSourceKind,
    ardContextSha256: result.ardContextSha256,
    policySha256: policyFingerprint(policy),
    graphSha256,
    catalogs,
    mcpSurfaces,
    findings: result.findings
      .map(({ ruleId, severity, message, location }) => ({ ruleId, severity, message, ...(location ? { location } : {}) }))
      .sort((a,b) => `${a.severity}:${a.ruleId}:${a.location ?? ''}:${a.message}`.localeCompare(`${b.severity}:${b.ruleId}:${b.location ?? ''}:${b.message}`))
  };
}

export function serializeLockfile(lock: CatalogLockfile): string {
  return prettyCanonicalJson(lock);
}
