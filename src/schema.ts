import type { AiCatalog, CatalogEntry, Finding, Policy } from './types.js';

function isObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

export function validateCatalog(value: unknown, location: string, policy: Policy): { catalog?: AiCatalog; findings: Finding[] } {
  const findings: Finding[] = [];
  if (!isObject(value)) return { findings: [{ ruleId: 'schema/catalog-object', severity: 'critical', message: 'Catalog must be a JSON object', location }] };
  if (typeof value.specVersion !== 'string' || !value.specVersion.trim()) findings.push({ ruleId: 'schema/spec-version', severity: 'error', message: 'specVersion must be a non-empty string', location });
  if (!isObject(value.host)) findings.push({ ruleId: 'schema/host', severity: 'error', message: 'host must be an object', location });
  if (!Array.isArray(value.entries)) findings.push({ ruleId: 'schema/entries', severity: 'critical', message: 'entries must be an array', location });
  if (!Array.isArray(value.entries)) return { findings };
  if (value.entries.length > policy.maxEntriesPerCatalog) findings.push({ ruleId: 'limits/entry-count', severity: 'critical', message: `Catalog has ${value.entries.length} entries; policy limit is ${policy.maxEntriesPerCatalog}`, location });

  const seen = new Set<string>();
  value.entries.forEach((raw, i) => {
    const loc = `${location}#entries/${i}`;
    if (!isObject(raw)) {
      findings.push({ ruleId: 'schema/entry-object', severity: 'error', message: 'Entry must be an object', location: loc });
      return;
    }
    const e = raw as Partial<CatalogEntry>;
    if (typeof e.identifier !== 'string' || !e.identifier) findings.push({ ruleId: 'schema/identifier', severity: 'error', message: 'identifier is required', location: loc });
    else if (seen.has(e.identifier)) findings.push({ ruleId: 'schema/duplicate-identifier', severity: 'error', message: `Duplicate identifier: ${e.identifier}`, location: loc });
    else seen.add(e.identifier);
    if (typeof e.displayName !== 'string' || !e.displayName) findings.push({ ruleId: 'schema/display-name', severity: 'error', message: 'displayName is required', location: loc });
    if (typeof e.type !== 'string' || !e.type) findings.push({ ruleId: 'schema/type', severity: 'error', message: 'type is required', location: loc });
    const hasUrl = typeof e.url === 'string' && e.url.length > 0;
    const hasData = Object.prototype.hasOwnProperty.call(e, 'data');
    if (hasUrl === hasData) findings.push({ ruleId: 'schema/url-xor-data', severity: 'error', message: 'Entry must have exactly one of url or data', location: loc });
    if (hasUrl) {
      try {
        const u = new URL(e.url!);
        if (policy.requireHttpsEntries && u.protocol !== 'https:') findings.push({ ruleId: 'transport/entry-https', severity: 'error', message: 'Entry URL must use HTTPS', location: loc });
        if (u.username || u.password) findings.push({ ruleId: 'transport/url-credentials', severity: 'critical', message: 'Entry URL must not embed credentials', location: loc });
      } catch {
        findings.push({ ruleId: 'schema/url', severity: 'error', message: 'Entry URL is invalid', location: loc });
      }
    }
    for (const key of ['tags', 'capabilities', 'representativeQueries'] as const) {
      const v = e[key];
      if (v !== undefined && (!Array.isArray(v) || v.some((x) => typeof x !== 'string'))) findings.push({ ruleId: `schema/${key}`, severity: 'warning', message: `${key} should be an array of strings`, location: loc });
    }
  });

  return { catalog: value as unknown as AiCatalog, findings };
}
