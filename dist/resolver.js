import { safeFetch, targetToCandidateUrls, validateOutboundUrl } from './net.js';
import { mergePolicy } from './policy.js';
import { canonicalJson, sha256 } from './canonical.js';
import { validateCatalog } from './schema.js';
import { assessEntryTrust } from './trust.js';
export const ARD_BASE_CONTEXT = {
    '@version': 1.1,
    '@vocab': 'https://agenticresourcediscovery.org/ns#',
    ard: 'https://agenticresourcediscovery.org/ns#',
    id: '@id', identifier: 'ard:identifier', displayName: 'ard:displayName', type: 'ard:mediaType',
    url: { '@id': 'ard:url', '@type': '@id' }, data: { '@id': 'ard:data', '@type': '@json' },
    representativeQueries: { '@id': 'ard:representativeQueries', '@container': '@set' },
    capabilities: { '@id': 'ard:capabilities', '@container': '@set' }, tags: { '@id': 'ard:tags', '@container': '@set' },
    description: 'ard:description', version: 'ard:version',
    updatedAt: { '@id': 'ard:updatedAt', '@type': 'http://www.w3.org/2001/XMLSchema#dateTime' },
    metadata: { '@id': 'ard:metadata', '@type': '@json' }, trustManifest: { '@id': 'ard:trustManifest', '@type': '@json' }
};
export const ARD_CONTEXT_SHA256 = sha256(canonicalJson(ARD_BASE_CONTEXT));
function isHtml(r) {
    return /text\/html/i.test(r.contentType ?? '') || /^\s*<!doctype html|^\s*<html\b/i.test(r.body);
}
function attrs(tag) {
    const out = {};
    const re = /([:\w-]+)\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/g;
    for (let m; (m = re.exec(tag));)
        out[m[1].toLowerCase()] = m[2] ?? m[3] ?? m[4] ?? '';
    return out;
}
export function findArdLink(html, base) {
    for (const tag of html.match(/<link\b[^>]*>/gi) ?? []) {
        const a = attrs(tag);
        const rel = (a.rel ?? '').toLowerCase().split(/\s+/);
        if (!rel.includes('ard') || !a.href)
            continue;
        try {
            return new URL(a.href, base).toString();
        }
        catch {
            continue;
        }
    }
    return undefined;
}
function parseJson(body, url, findings) {
    try {
        return JSON.parse(body);
    }
    catch {
        findings.push({ ruleId: 'parse/json', severity: 'critical', message: 'Response is not valid JSON', location: url });
        return undefined;
    }
}
async function resolveRoot(target, policy, fetcher, findings) {
    const explicitUrl = /^https?:\/\//i.test(target) ? validateOutboundUrl(target, policy) : undefined;
    const explicitPath = explicitUrl && explicitUrl.pathname !== '/' && explicitUrl.pathname !== '';
    if (explicitPath) {
        try {
            const r = await fetcher(explicitUrl.toString(), policy);
            if (r.status >= 200 && r.status < 300) {
                if (isHtml(r)) {
                    const link = findArdLink(r.body, r.url || explicitUrl.toString());
                    if (!link) {
                        findings.push({ ruleId: 'discovery/rel-ard', severity: 'error', message: 'HTML target does not advertise rel="ard"', location: r.url });
                        return { kind: 'explicit' };
                    }
                    const mf = await fetcher(link, policy);
                    if (mf.status >= 200 && mf.status < 300)
                        return { url: mf.url || link, fetch: mf, kind: 'rel-ard' };
                    findings.push({ ruleId: 'fetch/rel-ard', severity: 'error', message: `rel="ard" manifest returned HTTP ${mf.status}`, location: link });
                    return { kind: 'rel-ard' };
                }
                return { url: r.url || explicitUrl.toString(), fetch: r, kind: 'explicit' };
            }
            findings.push({ ruleId: 'fetch/http-status', severity: 'error', message: `Target returned HTTP ${r.status}`, location: explicitUrl.toString() });
        }
        catch (e) {
            findings.push({ ruleId: 'fetch/root', severity: 'critical', message: e instanceof Error ? e.message : String(e), location: explicitUrl.toString() });
        }
        return { kind: 'explicit' };
    }
    const candidates = targetToCandidateUrls(target, policy);
    for (let i = 0; i < candidates.length; i++) {
        const candidate = candidates[i];
        try {
            const r = await fetcher(candidate, policy);
            if (r.status >= 200 && r.status < 300) {
                if (i > 0)
                    findings.push({ ruleId: 'compat/ai-catalog-json', severity: 'warning', message: 'Using predecessor /.well-known/ai-catalog.json; ARD v0.91 consumers are required to fetch /.well-known/ard.json', location: r.url || candidate });
                return { url: r.url || candidate, fetch: r, kind: i === 0 ? 'ard' : 'legacy-ai-catalog' };
            }
            if (r.status !== 404 || i === candidates.length - 1)
                findings.push({ ruleId: 'fetch/http-status', severity: 'warning', message: `Manifest candidate returned HTTP ${r.status}`, location: candidate });
        }
        catch (e) {
            findings.push({ ruleId: 'fetch/root-candidate', severity: i === 0 ? 'warning' : 'error', message: e instanceof Error ? e.message : String(e), location: candidate });
        }
    }
    // HTML rel=ard is an additional discovery path, not a replacement for the required well-known fetch.
    try {
        const origin = explicitUrl ? explicitUrl.origin + '/' : new URL(`https://${target}`).origin + '/';
        const r = await fetcher(origin, policy);
        if (r.status >= 200 && r.status < 300 && isHtml(r)) {
            const link = findArdLink(r.body, r.url || origin);
            if (link) {
                const mf = await fetcher(link, policy);
                if (mf.status >= 200 && mf.status < 300) {
                    findings.push({ ruleId: 'discovery/rel-ard', severity: 'info', message: 'Resolved ARD manifest via HTML rel="ard" after well-known resolution was unavailable', location: link });
                    return { url: mf.url || link, fetch: mf, kind: 'rel-ard' };
                }
            }
        }
    }
    catch { /* well-known findings above remain authoritative */ }
    return { kind: 'ard' };
}
export async function resolveCatalogs(target, options = {}) {
    const policy = mergePolicy(options.policy);
    const fetcher = options.fetcher ?? ((url, p) => safeFetch(url, p, options.addressResolver));
    const findings = [];
    const catalogs = [];
    const trust = [];
    const seen = new Set();
    const identifierSources = new Map();
    const root = await resolveRoot(target, policy, fetcher, findings);
    const fallbackRoot = targetToCandidateUrls(target, policy)[0] ?? target;
    if (!root.url || !root.fetch)
        return { root: fallbackRoot, rootSourceKind: root.kind, ardContextSha256: ARD_CONTEXT_SHA256, catalogs, findings, trust };
    const queue = [{ url: root.url, depth: 0, prefetched: root.fetch }];
    while (queue.length) {
        const item = queue.shift();
        const normalized = new URL(item.url).toString();
        if (seen.has(normalized))
            continue;
        if (catalogs.length >= policy.maxCatalogs) {
            findings.push({ ruleId: 'limits/catalog-count', severity: 'critical', message: `Entry-source graph exceeds maxCatalogs=${policy.maxCatalogs}`, location: normalized });
            break;
        }
        if (item.depth > policy.maxDepth) {
            findings.push({ ruleId: 'limits/depth', severity: 'error', message: `Nested entry-source depth exceeds maxDepth=${policy.maxDepth}`, location: normalized });
            continue;
        }
        seen.add(normalized);
        let fetched;
        try {
            fetched = item.prefetched ?? await fetcher(normalized, policy);
        }
        catch (e) {
            findings.push({ ruleId: 'fetch/catalog', severity: 'error', message: e instanceof Error ? e.message : String(e), location: normalized });
            continue;
        }
        if (fetched.status < 200 || fetched.status >= 300) {
            findings.push({ ruleId: 'fetch/http-status', severity: 'error', message: `Nested entry source returned HTTP ${fetched.status}`, location: normalized });
            continue;
        }
        if (isHtml(fetched)) {
            findings.push({ ruleId: 'parse/unexpected-html', severity: 'error', message: 'Nested entry source returned HTML instead of an ARD manifest', location: normalized });
            continue;
        }
        const parsed = parseJson(fetched.body, normalized, findings);
        if (parsed === undefined)
            continue;
        const validated = validateCatalog(parsed, normalized, policy);
        findings.push(...validated.findings);
        if (!validated.catalog)
            continue;
        const catalog = validated.catalog;
        const record = { url: normalized, sourceHost: new URL(normalized).hostname.toLowerCase(), sha256: sha256(fetched.body), depth: item.depth, catalog };
        catalogs.push(record);
        for (const entry of catalog.entries) {
            if (!entry || typeof entry !== 'object' || typeof entry.identifier !== 'string')
                continue;
            const priorSource = identifierSources.get(entry.identifier);
            if (priorSource && priorSource !== normalized)
                findings.push({ ruleId: 'authority/identifier-collision', severity: 'critical', message: `Identifier ${entry.identifier} is asserted by multiple entry sources`, location: normalized, evidence: { firstSource: priorSource, secondSource: normalized } });
            else if (!priorSource)
                identifierSources.set(entry.identifier, normalized);
            const assessed = await assessEntryTrust(entry, normalized, policy, fetcher, options.trustVerifiers ?? []);
            trust.push(assessed.assessment);
            findings.push(...assessed.findings);
            if (entry.type === 'application/ai-catalog+json' && typeof entry.url === 'string') {
                if (item.depth >= policy.maxDepth)
                    findings.push({ ruleId: 'limits/depth', severity: 'error', message: `Nested entry source not followed because depth would exceed ${policy.maxDepth}`, location: entry.url });
                else
                    queue.push({ url: entry.url, depth: item.depth + 1 });
            }
        }
    }
    return {
        root: root.url,
        rootSourceKind: root.kind,
        ardContextSha256: ARD_CONTEXT_SHA256,
        catalogs: catalogs.sort((a, b) => a.url.localeCompare(b.url)),
        findings: findings.sort((a, b) => `${a.severity}:${a.ruleId}:${a.location ?? ''}:${a.message}`.localeCompare(`${b.severity}:${b.ruleId}:${b.location ?? ''}:${b.message}`)),
        trust: trust.sort((a, b) => a.identifier.localeCompare(b.identifier) || a.sourceCatalog.localeCompare(b.sourceCatalog))
    };
}
