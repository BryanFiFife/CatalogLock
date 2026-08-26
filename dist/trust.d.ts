import type { AiCatalog, CatalogEntry, Finding, TrustAssessment } from './types.js';
export declare function publisherFromIdentifier(identifier: string): string | undefined;
export declare function hostWithin(host: string, publisher: string): boolean;
export declare function identityHost(identity: string): string | undefined;
export declare function assessHostTrust(catalog: AiCatalog, sourceCatalog: string): Finding[];
export declare function assessEntryTrust(entry: CatalogEntry, sourceCatalog: string, requirePublisherMatch?: boolean): {
    assessment: TrustAssessment;
    findings: Finding[];
};
//# sourceMappingURL=trust.d.ts.map