import type { AiCatalog, CatalogEntry, Finding, Policy, TrustManifest } from './types.js';

function isObject(v: unknown): v is Record<string, unknown> { return !!v && typeof v === 'object' && !Array.isArray(v); }
const urnAir = /^urn:air:([A-Za-z0-9.-]+)(?::[A-Za-z0-9._-]+)+$/;

function validateContext(value: unknown, loc: string, findings: Finding[]): void {
  if (value === undefined) return;
  if (typeof value === 'string') {
    try { new URL(value); } catch { findings.push({ ruleId: 'schema/jsonld-context', severity: 'error', message: '@context string must be a valid URI', location: loc }); }
    return;
  }
  if (isObject(value) || Array.isArray(value)) return;
  findings.push({ ruleId: 'schema/jsonld-context', severity: 'error', message: '@context must be a URI, object or array', location: loc });
}

function validateTrust(value: unknown, loc: string, findings: Finding[]): void {
  if (value === undefined) return;
  if (!isObject(value)) { findings.push({ ruleId: 'schema/trust-manifest', severity: 'error', message: 'trustManifest must be an object', location: loc }); return; }
  const t = value as TrustManifest;
  if (typeof t.identity !== 'string' || !t.identity) findings.push({ ruleId: 'schema/trust-identity', severity: 'error', message: 'trustManifest.identity is required when trustManifest is present', location: loc });
  if (t.attestations !== undefined && (!Array.isArray(t.attestations) || t.attestations.some(a => !isObject(a)))) findings.push({ ruleId: 'schema/trust-attestations', severity: 'error', message: 'trustManifest.attestations must be an array of objects', location: loc });
  if (t.provenance !== undefined && (!Array.isArray(t.provenance) || t.provenance.some(a => !isObject(a)))) findings.push({ ruleId: 'schema/trust-provenance', severity: 'error', message: 'trustManifest.provenance must be an array of objects', location: loc });
  if (t.signature !== undefined && typeof t.signature !== 'string') findings.push({ ruleId: 'schema/trust-signature', severity: 'error', message: 'trustManifest.signature must be a string', location: loc });
}

export function validateCatalog(value: unknown, location: string, policy: Policy): { catalog?: AiCatalog; findings: Finding[] } {
  const findings: Finding[] = [];
  if (!isObject(value)) return { findings: [{ ruleId: 'schema/manifest-object', severity: 'critical', message: 'ARD manifest must be a JSON object', location }] };
  if (!Array.isArray(value.entries)) return { findings: [{ ruleId: 'schema/entries', severity: 'critical', message: 'ARD v0.91 manifest requires an entries array', location }] };
  if (value.entries.length > policy.maxEntriesPerCatalog) findings.push({ ruleId: 'limits/entry-count', severity: 'critical', message: `Manifest has ${value.entries.length} entries; policy limit is ${policy.maxEntriesPerCatalog}`, location });
  validateContext(value['@context'], `${location}#@context`, findings);
  if ('collections' in value) findings.push({ ruleId: 'compat/collections', severity: 'warning', message: 'Top-level collections is legacy and ignored by ARD v0.91', location });

  const seen = new Set<string>();
  value.entries.forEach((raw, i) => {
    const loc = `${location}#entries/${i}`;
    if (!isObject(raw)) { findings.push({ ruleId: 'schema/entry-object', severity: 'error', message: 'Entry must be an object', location: loc }); return; }
    const e = raw as Partial<CatalogEntry>;
    if (typeof e.identifier !== 'string' || !e.identifier) findings.push({ ruleId: 'schema/identifier', severity: 'error', message: 'identifier is required', location: loc });
    else if (!urnAir.test(e.identifier)) findings.push({ ruleId: 'schema/identifier', severity: 'error', message: `identifier is not a valid domain-anchored urn:air value: ${e.identifier}`, location: loc });
    else if (seen.has(e.identifier)) findings.push({ ruleId: 'schema/duplicate-identifier', severity: 'error', message: `Duplicate identifier: ${e.identifier}`, location: loc });
    else seen.add(e.identifier);
    if (typeof e.displayName !== 'string' || !e.displayName) findings.push({ ruleId: 'schema/display-name', severity: 'error', message: 'displayName is required', location: loc });
    if (typeof e.type !== 'string' || !e.type) findings.push({ ruleId: 'schema/type', severity: 'error', message: 'type is required', location: loc });
    const hasUrl = typeof e.url === 'string' && e.url.length > 0;
    const hasData = Object.prototype.hasOwnProperty.call(e, 'data');
    if (hasUrl === hasData) findings.push({ ruleId: 'schema/url-xor-data', severity: 'error', message: 'Entry must provide exactly one of url or data', location: loc });
    if (hasUrl) {
      try {
        const u = new URL(e.url!);
        if (policy.requireHttpsEntries && u.protocol !== 'https:') findings.push({ ruleId: 'transport/entry-https', severity: 'error', message: 'Entry URL must use HTTPS', location: loc });
        if (u.username || u.password) findings.push({ ruleId: 'transport/url-credentials', severity: 'critical', message: 'Entry URL must not embed credentials', location: loc });
      } catch { findings.push({ ruleId: 'schema/url', severity: 'error', message: 'Entry URL is invalid', location: loc }); }
    }
    validateContext(e['@context'], `${loc}/@context`, findings);
    if (typeof e['@id'] === 'string' && typeof e.identifier === 'string' && e['@id'] !== e.identifier) findings.push({ ruleId: 'schema/jsonld-id-mismatch', severity: 'error', message: '@id and identifier must denote the same resource', location: loc });
    for (const key of ['tags', 'capabilities', 'representativeQueries'] as const) {
      const v = e[key];
      if (v !== undefined && (!Array.isArray(v) || v.some(x => typeof x !== 'string'))) findings.push({ ruleId: `schema/${key}`, severity: 'error', message: `${key} must be an array of strings`, location: loc });
    }
    if (e.representativeQueries === undefined) findings.push({ ruleId: 'discovery/representative-queries', severity: 'warning', message: 'No representativeQueries; entry is valid but may not be semantically discoverable', location: loc });
    else if (Array.isArray(e.representativeQueries) && (e.representativeQueries.length < 2 || e.representativeQueries.length > 5)) findings.push({ ruleId: 'discovery/representative-queries-count', severity: 'warning', message: 'ARD recommends 2 to 5 representativeQueries', location: loc });
    if (e.metadata !== undefined && (!isObject(e.metadata) || Object.values(e.metadata).some(v => !['string','number','boolean'].includes(typeof v) && v !== null))) findings.push({ ruleId: 'schema/metadata', severity: 'error', message: 'metadata values must be string, number, boolean or null', location: loc });
    validateTrust(e.trustManifest, `${loc}/trustManifest`, findings);
  });
  return { catalog: value as unknown as AiCatalog, findings };
}
