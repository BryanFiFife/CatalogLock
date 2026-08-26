import type { CatalogLockfile, DiffChange, LockDiff, LockedEntry, Severity } from './types.js';
import { severityRank } from './policy.js';

const order: Severity[] = ['info', 'warning', 'error', 'critical'];

function entryMap(lock: CatalogLockfile): Map<string, { catalog: string; entry: LockedEntry }> {
  const map = new Map<string, { catalog: string; entry: LockedEntry }>();
  for (const c of lock.catalogs) for (const e of c.entries) map.set(e.identifier, { catalog: c.url, entry: e });
  return map;
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
    const old = bc.get(c)!; const cur = ac.get(c)!;
    if (old.sha256 !== cur.sha256) changes.push({ kind: 'catalog-changed', severity: 'error', identifier: c, message: `Catalog content changed: ${c}`, before: old.sha256, after: cur.sha256 });
  }

  const b = entryMap(before); const a = entryMap(after);
  for (const id of [...a.keys()].filter((x) => !b.has(x)).sort()) changes.push({ kind: 'resource-added', severity: 'warning', identifier: id, message: `Resource added: ${id}`, after: a.get(id) });
  for (const id of [...b.keys()].filter((x) => !a.has(x)).sort()) changes.push({ kind: 'resource-removed', severity: 'warning', identifier: id, message: `Resource removed: ${id}`, before: b.get(id) });
  for (const id of [...a.keys()].filter((x) => b.has(x)).sort()) {
    const old = b.get(id)!; const cur = a.get(id)!;
    const authorityChanged = old.entry.publisher !== cur.entry.publisher || old.catalog !== cur.catalog || old.entry.trustScore !== cur.entry.trustScore || old.entry.signaturePresent !== cur.entry.signaturePresent;
    if (authorityChanged) changes.push({ kind: 'authority-changed', severity: 'critical', identifier: id, message: `Trust/authority changed for ${id}`, before: old, after: cur });
    else if (old.entry.entrySha256 !== cur.entry.entrySha256) changes.push({ kind: 'resource-changed', severity: 'error', identifier: id, message: `Resource definition changed: ${id}`, before: old.entry, after: cur.entry });
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
      highestSeverity: order[Math.max(0, severityRank(highest))]!
    }
  };
}
