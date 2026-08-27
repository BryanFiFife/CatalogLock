import type { AddressResolver } from './net.js';
import type { FetchResult, Finding, McpSurfaceSnapshot, Policy, ResolveResult } from './types.js';
export type McpCardFetcher = (url: string, policy: Policy) => Promise<FetchResult>;
export type McpRequester = (url: string, body: unknown, policy: Policy, headers: Record<string, string>) => Promise<FetchResult>;
export interface McpInspectOptions {
    fetcher?: McpCardFetcher;
    requester?: McpRequester;
    addressResolver?: AddressResolver;
    env?: Record<string, string | undefined>;
}
export declare function inspectMcpSurfaces(result: ResolveResult, policy: Policy, options?: McpInspectOptions): Promise<{
    surfaces: McpSurfaceSnapshot[];
    findings: Finding[];
}>;
//# sourceMappingURL=mcp.d.ts.map