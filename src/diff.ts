import type {
  CatalogLockfile, DiffChange, DiffKind, LockDiff, LockedEntry, LockedMcpCollection,
  LockedMcpItem, McpProbeSnapshot, McpSurfaceSnapshot, Severity, TrustState
} from './types.js';
import { severityRank } from './policy.js';
import { canonicalJson, sha256 } from './canonical.js';

const severityOrder: Severity[] = ['info', 'warning', 'error', 'critical'];
const trustRank: Record<TrustState, number> = {
  invalid: 0,
  absent: 1,
  unsupported: 2,
  'present-unverified': 3,
  verified: 4
};

function entryMap(lock: CatalogLockfile): Map<string, { catalog: string; entry: LockedEntry }> {
  const map = new Map<string, { catalog: string; entry: LockedEntry }>();
  for (const c of lock.catalogs) for (const e of c.entries) map.set(e.identifier, { catalog: c.url, entry: e });
  return map;
}

function surfaceKey(s: McpSurfaceSnapshot): string {
  return typeof s.surfaceId === 'string' && s.surfaceId ? s.surfaceId : `${s.identifier}#legacy`;
}
function surfaceMap(lock: CatalogLockfile): Map<string, McpSurfaceSnapshot> {
  return new Map((lock.mcpSurfaces ?? []).map(s => [surfaceKey(s), s]));
}

function add(changes: DiffChange[], kind: DiffKind, severity: Severity, identifier: string, message: string, before?: unknown, after?: unknown): void {
  changes.push({ kind, severity, identifier, message, ...(before !== undefined ? { before } : {}), ...(after !== undefined ? { after } : {}) });
}

function itemMap(c?: LockedMcpCollection): Map<string, LockedMcpItem> {
  return new Map((c?.items ?? []).map(i => [i.key, i]));
}

function diffCache(changes: DiffChange[], id: string, label: string, before?: LockedMcpCollection, after?: LockedMcpCollection): void {
  if (!before || !after || before.cacheSha256 === after.cacheSha256) return;
  const privateBefore = before.caches.some(c => c.cacheScope === 'private');
  const publicAfter = after.caches.some(c => c.cacheScope === 'public');
  if (privateBefore && publicAfter) {
    add(changes, 'mcp-cache-scope-widened', 'critical', id, `${label} cache scope widened from private to public on ${id}`, before.caches, after.caches);
  } else {
    add(changes, 'mcp-cache-changed', 'warning', id, `${label} cache policy changed on ${id}`, before.caches, after.caches);
  }
}

function diffCollection(
  changes: DiffChange[], surfaceId: string, label: string, before: LockedMcpCollection | undefined,
  after: LockedMcpCollection | undefined, kinds: [DiffKind, DiffKind, DiffKind]
): void {
  if (!before && !after) return;
  if (!before && after) {
    for (const item of after.items) add(changes, kinds[0], 'critical', `${surfaceId}#${item.key}`, `New MCP ${label} appeared: ${item.key} on ${surfaceId}`, undefined, item);
    return;
  }
  if (before && !after) {
    for (const item of before.items) add(changes, kinds[1], 'warning', `${surfaceId}#${item.key}`, `MCP ${label} disappeared: ${item.key} on ${surfaceId}`, item);
    return;
  }
  const b = itemMap(before), a = itemMap(after);
  for (const key of [...a.keys()].filter(k => !b.has(k)).sort()) add(changes, kinds[0], 'critical', `${surfaceId}#${key}`, `New MCP ${label} appeared: ${key} on ${surfaceId}`, undefined, a.get(key));
  for (const key of [...b.keys()].filter(k => !a.has(k)).sort()) add(changes, kinds[1], 'warning', `${surfaceId}#${key}`, `MCP ${label} disappeared: ${key} on ${surfaceId}`, b.get(key));
  for (const key of [...a.keys()].filter(k => b.has(k)).sort()) {
    const old = b.get(key)!, cur = a.get(key)!;
    if (old.sha256 !== cur.sha256) add(changes, kinds[2], 'critical', `${surfaceId}#${key}`, `MCP ${label} definition changed: ${key} on ${surfaceId}`, old, cur);
  }
  diffCache(changes, surfaceId, `MCP ${label} list`, before, after);
}

function probeMap(s: McpSurfaceSnapshot): Map<string, McpProbeSnapshot> {
  return new Map((s.probes ?? []).map(p => [`${p.method}\0${p.key}`, p]));
}

function countKinds(changes: DiffChange[]): Record<string, number | Severity> & { highestSeverity: Severity } {
  const out: Record<string, number | Severity> & { highestSeverity: Severity } = { highestSeverity: 'info' };
  for (const c of changes) {
    out[c.kind] = Number(out[c.kind] ?? 0) + 1;
    if (severityRank(c.severity) > severityRank(out.highestSeverity)) out.highestSeverity = c.severity;
  }
  return out;
}

export function diffLockfiles(before: CatalogLockfile, after: CatalogLockfile): LockDiff {
  const changes: DiffChange[] = [];
  if (before.root !== after.root) add(changes, 'root-changed', 'critical', after.root, `Root entry source changed from ${before.root} to ${after.root}`, before.root, after.root);
  if (before.rootSourceKind !== after.rootSourceKind) add(changes, 'root-source-changed', 'error', after.root, 'ARD root discovery source changed', before.rootSourceKind, after.rootSourceKind);
  if (before.ardContextSha256 !== after.ardContextSha256) add(changes, 'ard-context-changed', 'critical', 'ard-context', 'Effective ARD base context changed', before.ardContextSha256, after.ardContextSha256);
  if (before.policySha256 !== after.policySha256) add(changes, 'policy-changed', 'error', 'policy', 'Effective CatalogLock policy changed', before.policySha256, after.policySha256);

  const bc = new Map(before.catalogs.map(c => [c.url, c]));
  const ac = new Map(after.catalogs.map(c => [c.url, c]));
  for (const c of [...ac.keys()].filter(x => !bc.has(x)).sort()) add(changes, 'catalog-added', 'error', c, `New entry-source authority entered the graph: ${c}`, undefined, ac.get(c));
  for (const c of [...bc.keys()].filter(x => !ac.has(x)).sort()) add(changes, 'catalog-removed', 'warning', c, `Entry source removed from graph: ${c}`, bc.get(c));
  for (const c of [...ac.keys()].filter(x => bc.has(x)).sort()) {
    const old = bc.get(c)!, cur = ac.get(c)!;
    if (old.sha256 !== cur.sha256) add(changes, 'catalog-changed', 'error', c, `Entry-source content changed: ${c}`, old.sha256, cur.sha256);
  }

  const b = entryMap(before), a = entryMap(after);
  for (const id of [...a.keys()].filter(x => !b.has(x)).sort()) add(changes, 'resource-added', 'warning', id, `Resource added: ${id}`, undefined, a.get(id));
  for (const id of [...b.keys()].filter(x => !a.has(x)).sort()) add(changes, 'resource-removed', 'warning', id, `Resource removed: ${id}`, b.get(id));
  for (const id of [...a.keys()].filter(x => b.has(x)).sort()) {
    const old = b.get(id)!, cur = a.get(id)!;
    const authorityChanged = old.entry.publisher !== cur.entry.publisher || old.catalog !== cur.catalog;
    if (authorityChanged) add(changes, 'authority-changed', 'critical', id, `Publisher/source authority changed for ${id}`, old, cur);
    if (old.entry.entrySha256 !== cur.entry.entrySha256) add(changes, 'resource-changed', 'error', id, `Resource definition changed: ${id}`, old.entry, cur.entry);
    const os = old.entry.trustState ?? 'absent', cs = cur.entry.trustState ?? 'absent';
    if (os !== cs || old.entry.trustEvidenceSha256 !== cur.entry.trustEvidenceSha256) {
      const regressed = trustRank[cs] < trustRank[os] || cs === 'invalid';
      add(changes, regressed ? 'trust-regressed' : 'trust-changed', regressed ? 'critical' : 'error', id,
        regressed ? `Verified/trust posture regressed for ${id}: ${os} -> ${cs}` : `Trust posture changed for ${id}: ${os} -> ${cs}`,
        { state: os, evidence: old.entry.trustEvidenceSha256 }, { state: cs, evidence: cur.entry.trustEvidenceSha256 });
    }
  }

  const bs = surfaceMap(before), as = surfaceMap(after);
  for (const id of [...as.keys()].filter(x => !bs.has(x)).sort()) add(changes, 'mcp-surface-added', 'error', id, `New contextual MCP surface appeared: ${id}`, undefined, as.get(id));
  for (const id of [...bs.keys()].filter(x => !as.has(x)).sort()) add(changes, 'mcp-surface-removed', 'error', id, `MCP surface is no longer observable: ${id}`, bs.get(id));
  for (const id of [...as.keys()].filter(x => bs.has(x)).sort()) {
    const old = bs.get(id)!, cur = as.get(id)!;
    if (old.cardSha256 !== cur.cardSha256) add(changes, 'mcp-card-changed', 'error', id, `MCP Server Card changed for ${id}`, old.cardSha256, cur.cardSha256);
    if (old.endpoint !== cur.endpoint) add(changes, 'mcp-endpoint-changed', 'critical', id, `MCP endpoint changed for ${id}`, old.endpoint, cur.endpoint);
    if (old.profileSha256 !== cur.profileSha256) add(changes, 'mcp-profile-changed', 'critical', id, `MCP inspection profile/capabilities changed for ${id}`, old.profileSha256, cur.profileSha256);
    if (old.discover?.sha256 !== cur.discover?.sha256) add(changes, 'mcp-discover-changed', 'critical', id, `MCP server/discover surface changed for ${id}`, old.discover, cur.discover);
    if (old.discover && cur.discover && old.discover.cache.cacheScope === 'private' && cur.discover.cache.cacheScope === 'public') {
      add(changes, 'mcp-cache-scope-widened', 'critical', id, `server/discover cache scope widened from private to public on ${id}`, old.discover.cache, cur.discover.cache);
    } else if (old.discover && cur.discover && canonicalJson(old.discover.cache) !== canonicalJson(cur.discover.cache)) {
      add(changes, 'mcp-cache-changed', 'warning', id, `server/discover cache policy changed on ${id}`, old.discover.cache, cur.discover.cache);
    }

    diffCollection(changes, id, 'tool', old.tools, cur.tools, ['mcp-tool-added','mcp-tool-removed','mcp-tool-changed']);
    diffCollection(changes, id, 'prompt', old.prompts, cur.prompts, ['mcp-prompt-added','mcp-prompt-removed','mcp-prompt-changed']);
    diffCollection(changes, id, 'resource', old.resources, cur.resources, ['mcp-resource-added','mcp-resource-removed','mcp-resource-changed']);
    diffCollection(changes, id, 'resource template', old.resourceTemplates, cur.resourceTemplates, ['mcp-resource-template-added','mcp-resource-template-removed','mcp-resource-template-changed']);

    const bp = probeMap(old), ap = probeMap(cur);
    for (const k of [...ap.keys()].filter(x => !bp.has(x)).sort()) add(changes, 'mcp-probe-added', 'critical', `${id}#probe:${k}`, `New read-only MCP probe surface appeared on ${id}: ${k}`, undefined, ap.get(k));
    for (const k of [...bp.keys()].filter(x => !ap.has(x)).sort()) add(changes, 'mcp-probe-removed', 'warning', `${id}#probe:${k}`, `Read-only MCP probe surface disappeared on ${id}: ${k}`, bp.get(k));
    for (const k of [...ap.keys()].filter(x => bp.has(x)).sort()) {
      const oldP = bp.get(k)!, curP = ap.get(k)!;
      if (oldP.sha256 !== curP.sha256 || sha256(canonicalJson(oldP.cache ?? null)) !== sha256(canonicalJson(curP.cache ?? null))) {
        add(changes, 'mcp-probe-changed', 'critical', `${id}#probe:${k}`, `Read-only MCP probe result changed on ${id}: ${k}`, oldP, curP);
      }
    }
  }

  changes.sort((x,y) => `${severityRank(y.severity)}:${x.kind}:${x.identifier}:${x.message}`.localeCompare(`${severityRank(x.severity)}:${y.kind}:${y.identifier}:${y.message}`));
  const highest = changes.reduce<Severity>((s,c) => severityRank(c.severity) > severityRank(s) ? c.severity : s, 'info');
  const blastRadius = countKinds(changes);
  blastRadius.highestSeverity = severityOrder[Math.max(0, severityRank(highest))]!;
  return { changed: changes.length > 0, changes, blastRadius };
}
