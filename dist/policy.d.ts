import type { Policy, Severity } from './types.js';
export declare const DEFAULT_POLICY: Policy;
export declare function severityRank(s: Severity): number;
export declare function mergePolicy(partial?: Partial<Policy>): Policy;
export declare function policyFingerprint(policy: Policy): string;
//# sourceMappingURL=policy.d.ts.map