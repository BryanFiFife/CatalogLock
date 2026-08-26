import type { AddressResolver } from './net.js';
import type { FetchResult, Policy, ResolveResult } from './types.js';
export type Fetcher = (url: string, policy: Policy) => Promise<FetchResult>;
export interface ResolveOptions {
    policy?: Partial<Policy>;
    fetcher?: Fetcher;
    addressResolver?: AddressResolver;
}
export declare function resolveCatalogs(target: string, options?: ResolveOptions): Promise<ResolveResult>;
//# sourceMappingURL=resolver.d.ts.map