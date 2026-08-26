import type { Policy, Severity } from './types.js';
import { canonicalJson, sha256 } from './canonical.js';

export const DEFAULT_POLICY: Policy = {
  maxDepth: 4,
  maxCatalogs: 32,
  maxEntriesPerCatalog: 5000,
  maxResponseBytes: 2_000_000,
  timeoutMs: 8000,
  maxRedirects: 3,
  allowedPorts: [443],
  allowHttp: false,
  allowCompatibilityArdJson: true,
  requirePublisherMatch: true,
  requireHttpsEntries: true,
  failOn: 'error'
};

const severities: Severity[] = ['info', 'warning', 'error', 'critical'];

export function severityRank(s: Severity): number {
  return severities.indexOf(s);
}

export function mergePolicy(partial: Partial<Policy> = {}): Policy {
  const p = { ...DEFAULT_POLICY, ...partial };
  if (!Number.isInteger(p.maxDepth) || p.maxDepth < 0 || p.maxDepth > 16) throw new Error('maxDepth must be 0..16');
  if (!Number.isInteger(p.maxCatalogs) || p.maxCatalogs < 1 || p.maxCatalogs > 1000) throw new Error('maxCatalogs must be 1..1000');
  if (!Number.isInteger(p.maxEntriesPerCatalog) || p.maxEntriesPerCatalog < 1) throw new Error('maxEntriesPerCatalog must be positive');
  if (!Number.isInteger(p.maxResponseBytes) || p.maxResponseBytes < 1024) throw new Error('maxResponseBytes must be at least 1024');
  if (!Number.isInteger(p.timeoutMs) || p.timeoutMs < 100) throw new Error('timeoutMs must be at least 100');
  if (!Number.isInteger(p.maxRedirects) || p.maxRedirects < 0 || p.maxRedirects > 10) throw new Error('maxRedirects must be 0..10');
  if (!Array.isArray(p.allowedPorts) || p.allowedPorts.some((x) => !Number.isInteger(x) || x < 1 || x > 65535)) throw new Error('allowedPorts contains invalid port');
  if (!severities.includes(p.failOn)) throw new Error('invalid failOn severity');
  return p;
}

export function policyFingerprint(policy: Policy): string {
  return sha256(canonicalJson(policy));
}
