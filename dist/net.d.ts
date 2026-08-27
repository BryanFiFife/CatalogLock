import type { FetchResult, Policy } from './types.js';
export interface AddressResolver {
    (hostname: string): Promise<string[]>;
}
export declare const systemResolve: AddressResolver;
export declare function isPublicIp(ip: string): boolean;
export declare function validateOutboundUrl(raw: string, policy: Policy): URL;
export declare function safeFetch(rawUrl: string, policy: Policy, resolver?: AddressResolver, redirects?: number): Promise<FetchResult>;
export declare function safePostJson(rawUrl: string, body: unknown, policy: Policy, resolver?: AddressResolver, headers?: Record<string, string>): Promise<FetchResult>;
export declare function targetToCandidateUrls(target: string, policy: Policy): string[];
//# sourceMappingURL=net.d.ts.map