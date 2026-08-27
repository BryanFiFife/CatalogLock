import type { CatalogLockfile, Policy, ResolveResult } from './types.js';
export declare const VERSION = "0.3.0";
export declare function createLockfile(result: ResolveResult & {
    mcpSurfaces?: CatalogLockfile['mcpSurfaces'];
}, policy: Policy): CatalogLockfile;
export declare function serializeLockfile(lock: CatalogLockfile): string;
//# sourceMappingURL=lockfile.d.ts.map