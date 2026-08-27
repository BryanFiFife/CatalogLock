import type { CatalogEntry, FetchResult, Finding, Policy, TrustAssessment, TrustManifest, TrustState } from './types.js';
export type TrustEvidenceFetcher = (url: string, policy: Policy) => Promise<FetchResult>;
export interface TrustVerifierContext {
    entry: CatalogEntry;
    sourceCatalog: string;
    policy: Policy;
    fetcher: TrustEvidenceFetcher;
}
export interface TrustVerifierResult {
    state: TrustState;
    verifiedEvidenceDigests?: string[];
    findings?: Finding[];
}
export type TrustFrameworkVerifier = (manifest: TrustManifest, context: TrustVerifierContext) => Promise<TrustVerifierResult | undefined>;
export declare function publisherFromIdentifier(identifier: string): string | undefined;
export declare function hostWithin(host: string, publisher: string): boolean;
export declare function identityHost(identity: string): string | undefined;
export declare function assessEntryTrust(entry: CatalogEntry, sourceCatalog: string, policy: Policy, fetcher: TrustEvidenceFetcher, verifiers?: TrustFrameworkVerifier[]): Promise<{
    assessment: TrustAssessment;
    findings: Finding[];
}>;
//# sourceMappingURL=trust.d.ts.map