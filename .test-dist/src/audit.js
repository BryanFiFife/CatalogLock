import { mergePolicy } from './policy.js';
import { resolveCatalogs } from './resolver.js';
import { inspectMcpSurfaces } from './mcp.js';
export async function auditCatalog(target, options = {}) {
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
    const result = {
        ...resolved,
        findings: [...resolved.findings, ...inspected.findings].sort((a, b) => `${a.severity}:${a.ruleId}:${a.location ?? ''}:${a.message}`.localeCompare(`${b.severity}:${b.ruleId}:${b.location ?? ''}:${b.message}`)),
        mcpSurfaces: inspected.surfaces
    };
    return { result, policy };
}
