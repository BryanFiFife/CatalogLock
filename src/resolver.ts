import type { AddressResolver } from './net.js';
import { safeFetch, targetToCandidateUrls } from './net.js';
import type { AiCatalog, CatalogRecord, FetchResult, Finding, Policy, ResolveResult } from './types.js';
import { mergePolicy } from './policy.js';
import { sha256 } from './canonical.js';
import { validateCatalog } from './schema.js';
import { assessEntryTrust, assessHostTrust } from './trust.js';

export type Fetcher = (url: string, policy: Policy) => Promise<FetchResult>;

export interface ResolveOptions {
  policy?: Partial<Policy>;
  fetcher?: Fetcher;
  addressResolver?: AddressResolver;
}

function jsonParse(body: string, url: string, findings: Finding[]): unknown {
  try { return JSON.parse(body); }
  catch { findings.push({ ruleId: 'parse/json', severity: 'critical', message: 'Response is not valid JSON', location: url }); return undefined; }
}

export async function resolveCatalogs(target: string, options: ResolveOptions = {}): Promise<ResolveResult> {
  const policy = mergePolicy(options.policy);
  const fetcher: Fetcher = options.fetcher ?? ((url, p) => safeFetch(url, p, options.addressResolver));
  const findings: Finding[] = [];
  const catalogs: CatalogRecord[] = [];
  const trust = [] as ResolveResult['trust'];
  const seen = new Set<string>();
  const identifierSources = new Map<string, string>();

  let rootUrl: string | undefined;
  let rootFetch: FetchResult | undefined;
  const candidates = targetToCandidateUrls(target, policy);
  for (let i = 0; i < candidates.length; i++) {
    const candidate = candidates[i]!;
    try {
      const result = await fetcher(candidate, policy);
      if (result.status >= 200 && result.status < 300) {
        rootUrl = result.url || candidate;
        rootFetch = result;
        if (i > 0) findings.push({ ruleId: 'compat/ard-json', severity: 'warning', message: 'Using compatibility /.well-known/ard.json; current ARD publisher path is /.well-known/ai-catalog.json', location: rootUrl });
        break;
      }
      if (result.status !== 404 || i === candidates.length - 1) findings.push({ ruleId: 'fetch/http-status', severity: 'error', message: `Catalog returned HTTP ${result.status}`, location: candidate });
    } catch (err) {
      findings.push({ ruleId: 'fetch/root', severity: 'critical', message: err instanceof Error ? err.message : String(err), location: candidate });
      if (i === 0) break; // security failure must not silently fall through to a second path.
    }
  }
  if (!rootUrl || !rootFetch) return { root: candidates[0]!, catalogs, findings, trust };

  const queue: Array<{ url: string; depth: number; prefetched?: FetchResult }> = [{ url: rootUrl, depth: 0, prefetched: rootFetch }];
  while (queue.length) {
    const item = queue.shift()!;
    const normalized = new URL(item.url).toString();
    if (seen.has(normalized)) continue;
    if (catalogs.length >= policy.maxCatalogs) {
      findings.push({ ruleId: 'limits/catalog-count', severity: 'critical', message: `Catalog graph exceeds maxCatalogs=${policy.maxCatalogs}`, location: normalized });
      break;
    }
    if (item.depth > policy.maxDepth) {
      findings.push({ ruleId: 'limits/depth', severity: 'error', message: `Nested catalog depth exceeds maxDepth=${policy.maxDepth}`, location: normalized });
      continue;
    }
    seen.add(normalized);

    let fetched: FetchResult;
    try { fetched = item.prefetched ?? await fetcher(normalized, policy); }
    catch (err) { findings.push({ ruleId: 'fetch/catalog', severity: 'error', message: err instanceof Error ? err.message : String(err), location: normalized }); continue; }
    if (fetched.status < 200 || fetched.status >= 300) {
      findings.push({ ruleId: 'fetch/http-status', severity: 'error', message: `Nested catalog returned HTTP ${fetched.status}`, location: normalized });
      continue;
    }
    const parsed = jsonParse(fetched.body, normalized, findings);
    if (parsed === undefined) continue;
    const validated = validateCatalog(parsed, normalized, policy);
    findings.push(...validated.findings);
    if (!validated.catalog) continue;
    const catalog = validated.catalog as AiCatalog;
    const record: CatalogRecord = { url: normalized, sourceHost: new URL(normalized).hostname.toLowerCase(), sha256: sha256(fetched.body), depth: item.depth, catalog };
    catalogs.push(record);
    findings.push(...assessHostTrust(catalog, normalized));

    for (const entry of catalog.entries) {
      if (!entry || typeof entry !== 'object' || typeof entry.identifier !== 'string') continue;
      const priorSource = identifierSources.get(entry.identifier);
      if (priorSource && priorSource !== normalized) {
        findings.push({ ruleId: 'authority/identifier-collision', severity: 'critical', message: `Identifier ${entry.identifier} is asserted by multiple catalogs`, location: normalized, evidence: { firstSource: priorSource, secondSource: normalized } });
      } else if (!priorSource) identifierSources.set(entry.identifier, normalized);
      const assessed = assessEntryTrust(entry, normalized, policy.requirePublisherMatch);
      trust.push(assessed.assessment);
      findings.push(...assessed.findings);
      if (entry.type === 'application/ai-catalog+json' && typeof entry.url === 'string') {
        if (item.depth >= policy.maxDepth) findings.push({ ruleId: 'limits/depth', severity: 'error', message: `Nested catalog not followed because depth would exceed ${policy.maxDepth}`, location: entry.url });
        else queue.push({ url: entry.url, depth: item.depth + 1 });
      }
    }
  }

  return { root: rootUrl, catalogs: catalogs.sort((a, b) => a.url.localeCompare(b.url)), findings: findings.sort((a,b) => `${a.severity}:${a.ruleId}:${a.location ?? ''}:${a.message}`.localeCompare(`${b.severity}:${b.ruleId}:${b.location ?? ''}:${b.message}`)), trust: trust.sort((a,b) => a.identifier.localeCompare(b.identifier) || a.sourceCatalog.localeCompare(b.sourceCatalog)) };
}
