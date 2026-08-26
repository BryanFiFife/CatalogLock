export type Severity = 'info' | 'warning' | 'error' | 'critical';

export interface Finding {
  ruleId: string;
  severity: Severity;
  message: string;
  location?: string;
  evidence?: Record<string, unknown>;
}

export interface TrustManifest {
  identity?: string;
  identityType?: string;
  attestations?: Array<{ type?: string; uri?: string; [key: string]: unknown }>;
  provenance?: unknown;
  signature?: unknown;
  [key: string]: unknown;
}

export interface CatalogEntry {
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
  metadata?: Record<string, unknown>;
  trustManifest?: TrustManifest;
  [key: string]: unknown;
}

export interface AiCatalog {
  specVersion: string;
  host: {
    displayName?: string;
    identifier?: string;
    trustManifest?: TrustManifest;
    [key: string]: unknown;
  };
  entries: CatalogEntry[];
  [key: string]: unknown;
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
  allowCompatibilityArdJson: boolean;
  requirePublisherMatch: boolean;
  requireHttpsEntries: boolean;
  failOn: Severity;
}

export interface FetchResult {
  url: string;
  status: number;
  body: string;
  contentType?: string;
  location?: string;
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
  score: number;
}

export interface ResolveResult {
  root: string;
  catalogs: CatalogRecord[];
  findings: Finding[];
  trust: TrustAssessment[];
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
  lockVersion: 1;
  generatedBy: string;
  root: string;
  policySha256: string;
  graphSha256: string;
  catalogs: LockedCatalog[];
  findings: Array<Pick<Finding, 'ruleId' | 'severity' | 'message' | 'location'>>;
}

export interface DiffChange {
  kind: 'root-changed' | 'policy-changed' | 'catalog-added' | 'catalog-removed' | 'catalog-changed' | 'resource-added' | 'resource-removed' | 'resource-changed' | 'authority-changed';
  severity: Severity;
  identifier: string;
  message: string;
  before?: unknown;
  after?: unknown;
}

export interface LockDiff {
  changed: boolean;
  changes: DiffChange[];
  blastRadius: {
    addedCatalogs: number;
    removedCatalogs: number;
    changedCatalogs: number;
    policyChanges: number;
    rootChanges: number;
    addedResources: number;
    removedResources: number;
    changedResources: number;
    authorityChanges: number;
    highestSeverity: Severity;
  };
}
