import type { AuditResult, Policy } from './types.js';
import { type ResolveOptions } from './resolver.js';
import { type McpInspectOptions } from './mcp.js';
export interface AuditOptions extends ResolveOptions, McpInspectOptions {
}
export declare function auditCatalog(target: string, options?: AuditOptions): Promise<{
    result: AuditResult;
    policy: Policy;
}>;
//# sourceMappingURL=audit.d.ts.map