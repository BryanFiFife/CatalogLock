import type { CatalogLockfile, DiffChange, LockDiff, LockedEntry, McpSurfaceSnapshot, Severity } from './types.js';
import { severityRank } from './policy.js';

const order: Severity[] = ['info', 'warning', 'error', 'critical'];

function entryMap(lock: CatalogLockfile): Map<string, { catalog: string; entry: LockedEntry }> {
  const map = new Map<string, { catalog: string; entry: LockedEntry }>();
  for (const c of lock.catalogs) for (const e of c.entries) map.set(e.identifier, { catalog: c.url, entry: e });
  return map;
}

function surfaceMap(lock: CatalogLockfile): Map<string, McpSurfaceSnapshot> {
  return new Map((lock.mcpSurfaces ?? []).map((s) => [s.identifier, s]));
}

export function diffLockfiles(before: CatalogLockfile, after: CatalogLockfile): LockDiff {
  const changes: DiffChange[] = [];
  if (before.root !== after.root) changes.push({ kind: 'root-changed', severity: 'critical', identifier: after.root, message: `Root catalog changed from ${before.root} to ${after.root}`, before: before.root, after: after.root });
  if (before.policySha256 !== after.policySha256) changes.push({ kind: 'policy-changed', severity: 'error', identifier: 'policy', message: 'Effective CatalogLock policy changed', before: before.policySha256, after: after.policySha256 });

  const bc = new Map(before.catalogs.map((c) => [c.url, c]));
  const ac = new Map(after.catalogs.map((c) => [c.url, c]));
  for (const c of [...ac.keys()].filter((x) => !bc.has(x)).sort()) changes.push({ kind: 'catalog-added', severity: 'error', identifier: c, message: `New catalog authority entered the graph: ${c}` });
  for (const c of [...bc.keys()].filter((x) => !ac.has(x)).sort()) changes.push({ kind: 'catalog-removed', severity: 'warning', identifier: c, message: `Catalog removed from graph: ${c}` });
  for (const c of [...ac.keys()].filter((x) => bc.has(x)).sort()) {
    const old = bc.get(c)!;
    const cur = ac.get(c)!;
    if (old.sha256 !== cur.sha256) changes.push({ kind: 'catalog-changed', severity: 'error', identifier: c, message: `Catalog content changed: ${c}`, before: old.sha256, after: cur.sha256 });
  }

  const b = entryMap(before);
  const a = entryMap(after);
  for (const id of [...a.keys()].filter((x) => !b.has(x)).sort()) changes.push({ kind: 'resource-added', severity: 'warning', identifier: id, message: `Resource added: ${id}`, after: a.get(id) });
  for (const id of [...b.keys()].filter((x) => !a.has(x)).sort()) changes.push({ kind: 'resource-removed', severity: 'warning', identifier: id, message: `Resource removed: ${id}`, before: b.get(id) });
  for (const id of [...a.keys()].filter((x) => b.has(x)).sort()) {
    const old = b.get(id)!;
    const cur = a.get(id)!;
    const authorityChanged = old.entry.publisher !== cur.entry.publisher || old.catalog !== cur.catalog || old.entry.trustScore !== cur.entry.trustScore || old.entry.signaturePresent !== cur.entry.signaturePresent;
    if (authorityChanged) changes.push({ kind: 'authority-changed', severity: 'critical', identifier: id, message: `Trust/authority changed for ${id}`, before: old, after: cur });
    else if (old.entry.entrySha256 !== cur.entry.entrySha256) changes.push({ kind: 'resource-changed', severity: 'error', identifier: id, message: `Resource definition changed: ${id}`, before: old.entry, after: cur.entry });
  }

  const bs = surfaceMap(before);
  const as = surfaceMap(after);
  for (const id of [...as.keys()].filter((x) => !bs.has(x)).sort()) {
    changes.push({ kind: 'mcp-surface-added', severity: 'warning', identifier: id, message: `MCP tool surface is now locked: ${id}`, after: as.get(id) });
  }
  for (const id of [...bs.keys()].filter((x) => !as.has(x)).sort()) {
    changes.push({ kind: 'mcp-surface-removed', severity: 'error', identifier: id, message: `MCP tool surface is no longer observable: ${id}`, before: bs.get(id) });
  }
  for (const id of [...as.keys()].filter((x) => bs.has(x)).sort()) {
    const old = bs.get(id)!;
    const cur = as.get(id)!;
    if (old.cardSha256 !== cur.cardSha256) {
      changes.push({ kind: 'mcp-card-changed', severity: 'error', identifier: id, message: `MCP Server Card changed for ${id}`, before: old.cardSha256, after: cur.cardSha256 });
    }
    if (old.endpoint !== cur.endpoint) {
      changes.push({ kind: 'mcp-endpoint-changed', severity: 'critical', identifier: id, message: `MCP endpoint changed for ${id}`, before: old.endpoint, after: cur.endpoint });
    }
    const oldTools = new Map(old.tools.map((t) => [t.name, t]));
    const curTools = new Map(cur.tools.map((t) => [t.name, t]));
    for (const name of [...curTools.keys()].filter((x) => !oldTools.has(x)).sort()) {
      changes.push({
        kind: 'mcp-tool-added',
        severity: 'critical',
        identifier: `${id}#${name}`,
        message: `New executable MCP tool appeared: ${name} on ${id}`,
        after: curTools.get(name)
      });
    }
    for (const name of [...oldTools.keys()].filter((x) => !curTools.has(x)).sort()) {
      changes.push({
        kind: 'mcp-tool-removed',
        severity: 'warning',
        identifier: `${id}#${name}`,
        message: `MCP tool disappeared: ${name} on ${id}`,
        before: oldTools.get(name)
      });
    }
    for (const name of [...curTools.keys()].filter((x) => oldTools.has(x)).sort()) {
      const oldTool = oldTools.get(name)!;
      const curTool = curTools.get(name)!;
      if (oldTool.toolSha256 !== curTool.toolSha256) {
        changes.push({
          kind: 'mcp-tool-changed',
          severity: 'critical',
          identifier: `${id}#${name}`,
          message: `MCP tool definition/schema changed: ${name} on ${id}`,
          before: oldTool,
          after: curTool
        });
      }
    }
  }

  const highest = changes.reduce<Severity>((s, c) => severityRank(c.severity) > severityRank(s) ? c.severity : s, 'info');
  return {
    changed: changes.length > 0,
    changes,
    blastRadius: {
      addedCatalogs: changes.filter((c) => c.kind === 'catalog-added').length,
      removedCatalogs: changes.filter((c) => c.kind === 'catalog-removed').length,
      changedCatalogs: changes.filter((c) => c.kind === 'catalog-changed').length,
      policyChanges: changes.filter((c) => c.kind === 'policy-changed').length,
      rootChanges: changes.filter((c) => c.kind === 'root-changed').length,
      addedResources: changes.filter((c) => c.kind === 'resource-added').length,
      removedResources: changes.filter((c) => c.kind === 'resource-removed').length,
      changedResources: changes.filter((c) => c.kind === 'resource-changed').length,
      authorityChanges: changes.filter((c) => c.kind === 'authority-changed').length,
      addedMcpSurfaces: changes.filter((c) => c.kind === 'mcp-surface-added').length,
      removedMcpSurfaces: changes.filter((c) => c.kind === 'mcp-surface-removed').length,
      changedMcpCards: changes.filter((c) => c.kind === 'mcp-card-changed').length,
      changedMcpEndpoints: changes.filter((c) => c.kind === 'mcp-endpoint-changed').length,
      addedMcpTools: changes.filter((c) => c.kind === 'mcp-tool-added').length,
      removedMcpTools: changes.filter((c) => c.kind === 'mcp-tool-removed').length,
      changedMcpTools: changes.filter((c) => c.kind === 'mcp-tool-changed').length,
      highestSeverity: order[Math.max(0, severityRank(highest))]!
    }
  };
}
