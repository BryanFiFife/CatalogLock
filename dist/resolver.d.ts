import type { AddressResolver } from './net.js';
import type { FetchResult, Policy, ResolveResult } from './types.js';
import { type TrustFrameworkVerifier } from './trust.js';
export type Fetcher = (url: string, policy: Policy) => Promise<FetchResult>;
export interface ResolveOptions {
    policy?: Partial<Policy>;
    fetcher?: Fetcher;
    addressResolver?: AddressResolver;
    trustVerifiers?: TrustFrameworkVerifier[];
}
export declare const ARD_BASE_CONTEXT: {
    readonly '@version': 1.1;
    readonly '@vocab': "https://agenticresourcediscovery.org/ns#";
    readonly ard: "https://agenticresourcediscovery.org/ns#";
    readonly id: "@id";
    readonly identifier: "ard:identifier";
    readonly displayName: "ard:displayName";
    readonly type: "ard:mediaType";
    readonly url: {
        readonly '@id': "ard:url";
        readonly '@type': "@id";
    };
    readonly data: {
        readonly '@id': "ard:data";
        readonly '@type': "@json";
    };
    readonly representativeQueries: {
        readonly '@id': "ard:representativeQueries";
        readonly '@container': "@set";
    };
    readonly capabilities: {
        readonly '@id': "ard:capabilities";
        readonly '@container': "@set";
    };
    readonly tags: {
        readonly '@id': "ard:tags";
        readonly '@container': "@set";
    };
    readonly description: "ard:description";
    readonly version: "ard:version";
    readonly updatedAt: {
        readonly '@id': "ard:updatedAt";
        readonly '@type': "http://www.w3.org/2001/XMLSchema#dateTime";
    };
    readonly metadata: {
        readonly '@id': "ard:metadata";
        readonly '@type': "@json";
    };
    readonly trustManifest: {
        readonly '@id': "ard:trustManifest";
        readonly '@type': "@json";
    };
};
export declare const ARD_CONTEXT_SHA256: string;
export declare function findArdLink(html: string, base: string): string | undefined;
export declare function resolveCatalogs(target: string, options?: ResolveOptions): Promise<ResolveResult>;
//# sourceMappingURL=resolver.d.ts.map