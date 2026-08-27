export type Severity = 'info' | 'warning' | 'error' | 'critical';
export type TrustState = 'absent' | 'verified' | 'present-unverified' | 'unsupported' | 'invalid';
export interface Finding {
    ruleId: string;
    severity: Severity;
    message: string;
    location?: string;
    evidence?: Record<string, unknown>;
}
export interface TrustSchema {
    identifier?: string;
    version?: string;
    governanceUri?: string;
    verificationMethods?: string[];
    [key: string]: unknown;
}
export interface TrustAttestation {
    type?: string;
    uri?: string;
    mediaType?: string;
    digest?: string;
    [key: string]: unknown;
}
export interface TrustProvenance {
    relation?: string;
    sourceId?: string;
    sourceDigest?: string;
    [key: string]: unknown;
}
export interface TrustManifest {
    identity?: string;
    identityType?: string;
    trustSchema?: TrustSchema;
    attestations?: TrustAttestation[];
    provenance?: TrustProvenance[];
    signature?: string;
    jwksUri?: string;
    verificationJwksUri?: string;
    [key: string]: unknown;
}
export interface CatalogEntry {
    '@context'?: string | Record<string, unknown> | unknown[];
    '@id'?: string;
    identifier: string;
    displayName: string;
    type: string;
    url?: string;
    data?: unknown;
    description?: string;
    tags?: string[];
    capabilities?: string[];
    representativeQueries?: string[];
    version?: string;
    updatedAt?: string;
    metadata?: Record<string, string | number | boolean | null>;
    trustManifest?: TrustManifest;
    [key: string]: unknown;
}
export interface AiCatalog {
    entries: CatalogEntry[];
    specVersion?: string;
    host?: Record<string, unknown>;
    '@context'?: unknown;
    [key: string]: unknown;
}
export interface McpProfile {
    name: string;
    clientCapabilities: Record<string, unknown>;
    headersFromEnv?: Record<string, string>;
}
export interface McpPromptProbe {
    identifier?: string;
    profile?: string;
    remoteId?: string;
    name: string;
    arguments?: Record<string, string>;
}
export interface McpResourceProbe {
    identifier?: string;
    profile?: string;
    remoteId?: string;
    uri: string;
}
export interface McpExtensionProbe {
    identifier?: string;
    profile?: string;
    remoteId?: string;
    method: string;
    params?: Record<string, unknown>;
    name?: string;
    uri?: string;
    cacheable?: boolean;
    readOnly: true;
}
export interface Policy {
    maxDepth: number;
    maxCatalogs: number;
    maxEntriesPerCatalog: number;
    maxResponseBytes: number;
    timeoutMs: number;
    maxRedirects: number;
    allowedPorts: number[];
    allowHttp: boolean;
    allowCompatibilityAiCatalogJson: boolean;
    requirePublisherMatch: boolean;
    requireHttpsEntries: boolean;
    inspectMcpPrimitives: boolean;
    inspectMcpDiscover: boolean;
    /** Deprecated compatibility alias. mergePolicy maps it to inspectMcpPrimitives. */
    inspectMcpTools?: boolean;
    requireMcpInspection: boolean;
    maxMcpPages: number;
    maxMcpItems: number;
    mcpProtocolVersion: string;
    mcpProfiles: McpProfile[];
    mcpPromptProbes: McpPromptProbe[];
    mcpResourceProbes: McpResourceProbe[];
    mcpExtensionProbes: McpExtensionProbe[];
    requireVerifiedTrust: boolean;
    maxTrustEvidenceBytes: number;
    allowedTrustAlgorithms: string[];
    failOn: Severity;
}
export interface FetchResult {
    url: string;
    status: number;
    body: string;
    bodyBytes?: Uint8Array;
    contentType?: string;
    location?: string;
    headers?: Record<string, string>;
}
export interface CatalogRecord {
    url: string;
    sourceHost: string;
    sha256: string;
    depth: number;
    catalog: AiCatalog;
}
export interface TrustAssessment {
    identifier: string;
    sourceCatalog: string;
    publisher?: string;
    publisherMatchesSource: boolean;
    entryUrlHost?: string;
    entryUrlWithinPublisher: boolean;
    identity?: string;
    identityMatchesPublisher?: boolean;
    signaturePresent: boolean;
    attestations: string[];
    state: TrustState;
    verifiedEvidenceDigests: string[];
    trustEvidenceSha256?: string;
    score: number;
}
export interface ResolveResult {
    root: string;
    rootSourceKind: 'ard' | 'legacy-ai-catalog' | 'rel-ard' | 'explicit';
    ardContextSha256: string;
    catalogs: CatalogRecord[];
    findings: Finding[];
    trust: TrustAssessment[];
}
export interface McpCachePolicy {
    ttlMs: number;
    cacheScope: 'public' | 'private';
}
export interface LockedMcpItem {
    key: string;
    sha256: string;
}
export interface LockedMcpCollection {
    items: LockedMcpItem[];
    itemsSha256: string;
    pages: number;
    cacheSha256: string;
    caches: McpCachePolicy[];
}
export interface McpDiscoverSnapshot {
    sha256: string;
    supportedVersions: string[];
    capabilitiesSha256: string;
    extensionsSha256?: string;
    instructionsSha256?: string;
    serverInfoSha256?: string;
    cache: McpCachePolicy;
}
export interface McpProbeSnapshot {
    method: string;
    key: string;
    sha256: string;
    cache?: McpCachePolicy;
}
export interface McpSurfaceSnapshot {
    surfaceId: string;
    identifier: string;
    remoteId: string;
    remoteIndex: number;
    cardUrl?: string;
    cardSha256: string;
    endpoint: string;
    protocolVersion: string;
    profile: string;
    profileSha256: string;
    discover?: McpDiscoverSnapshot;
    tools?: LockedMcpCollection;
    prompts?: LockedMcpCollection;
    resources?: LockedMcpCollection;
    resourceTemplates?: LockedMcpCollection;
    probes: McpProbeSnapshot[];
    surfaceSha256: string;
}
export interface AuditResult extends ResolveResult {
    mcpSurfaces: McpSurfaceSnapshot[];
}
export interface LockedEntry {
    identifier: string;
    displayName: string;
    type: string;
    url?: string;
    dataSha256?: string;
    version?: string;
    publisher?: string;
    entrySha256: string;
    trustScore: number;
    trustState: TrustState;
    trustEvidenceSha256?: string;
    signaturePresent: boolean;
    capabilities: string[];
    tags: string[];
}
export interface LockedCatalog {
    url: string;
    sha256: string;
    entries: LockedEntry[];
}
export interface CatalogLockfile {
    lockVersion: 1 | 2 | 3;
    generatedBy: string;
    root: string;
    rootSourceKind?: ResolveResult['rootSourceKind'];
    ardContextSha256?: string;
    policySha256: string;
    graphSha256: string;
    catalogs: LockedCatalog[];
    mcpSurfaces?: McpSurfaceSnapshot[];
    findings: Array<Pick<Finding, 'ruleId' | 'severity' | 'message' | 'location'>>;
}
export type DiffKind = 'root-changed' | 'root-source-changed' | 'ard-context-changed' | 'policy-changed' | 'catalog-added' | 'catalog-removed' | 'catalog-changed' | 'resource-added' | 'resource-removed' | 'resource-changed' | 'authority-changed' | 'trust-regressed' | 'trust-changed' | 'mcp-surface-added' | 'mcp-surface-removed' | 'mcp-card-changed' | 'mcp-endpoint-changed' | 'mcp-profile-changed' | 'mcp-discover-changed' | 'mcp-tool-added' | 'mcp-tool-removed' | 'mcp-tool-changed' | 'mcp-prompt-added' | 'mcp-prompt-removed' | 'mcp-prompt-changed' | 'mcp-resource-added' | 'mcp-resource-removed' | 'mcp-resource-changed' | 'mcp-resource-template-added' | 'mcp-resource-template-removed' | 'mcp-resource-template-changed' | 'mcp-cache-changed' | 'mcp-cache-scope-widened' | 'mcp-probe-added' | 'mcp-probe-removed' | 'mcp-probe-changed';
export interface DiffChange {
    kind: DiffKind;
    severity: Severity;
    identifier: string;
    message: string;
    before?: unknown;
    after?: unknown;
}
export interface LockDiff {
    changed: boolean;
    changes: DiffChange[];
    blastRadius: Record<string, number | Severity> & {
        highestSeverity: Severity;
    };
}
//# sourceMappingURL=types.d.ts.map