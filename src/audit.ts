import type { AuditResult, Policy } from './types.js';
import { mergePolicy } from './policy.js';
import { resolveCatalogs, type ResolveOptions } from './resolver.js';
import { inspectMcpSurfaces, type McpInspectOptions } from './mcp.js';

export interface AuditOptions extends ResolveOptions, McpInspectOptions {}

export async function auditCatalog(target: string, options: AuditOptions = {}): Promise<{ result: AuditResult; policy: Policy }> {
  const policy = mergePolicy(options.policy);
  const resolved = await resolveCatalogs(target, {
    policy,
    ...(options.fetcher ? { fetcher: options.fetcher } : {}),
    ...(options.addressResolver ? { addressResolver: options.addressResolver } : {})
  });
  const inspected = await inspectMcpSurfaces(resolved, policy, {
    ...(options.fetcher ? { fetcher: options.fetcher } : {}),
    ...(options.requester ? { requester: options.requester } : {}),
    ...(options.addressResolver ? { addressResolver: options.addressResolver } : {})
  });
  const result: AuditResult = {
    ...resolved,
    findings: [...resolved.findings, ...inspected.findings].sort((a,b) => `${a.severity}:${a.ruleId}:${a.location ?? ''}:${a.message}`.localeCompare(`${b.severity}:${b.ruleId}:${b.location ?? ''}:${b.message}`)),
    mcpSurfaces: inspected.surfaces
  };
  return { result, policy };
}
