import type { McpExtensionProbe, McpProfile, Policy, Severity } from './types.js';
import { canonicalJson, sha256 } from './canonical.js';

export const DEFAULT_POLICY: Policy = {
  maxDepth: 4,
  maxCatalogs: 32,
  maxEntriesPerCatalog: 5000,
  maxResponseBytes: 2_000_000,
  timeoutMs: 8000,
  maxRedirects: 3,
  allowedPorts: [443],
  allowHttp: false,
  allowCompatibilityAiCatalogJson: true,
  requirePublisherMatch: true,
  requireHttpsEntries: true,
  inspectMcpPrimitives: true,
  inspectMcpDiscover: true,
  requireMcpInspection: false,
  maxMcpPages: 25,
  maxMcpItems: 5000,
  mcpProtocolVersion: '2026-07-28',
  mcpProfiles: [{ name: 'public', clientCapabilities: {} }],
  mcpPromptProbes: [],
  mcpResourceProbes: [],
  mcpExtensionProbes: [],
  requireVerifiedTrust: false,
  maxTrustEvidenceBytes: 2_000_000,
  allowedTrustAlgorithms: ['RS256', 'ES256', 'EdDSA'],
  failOn: 'error'
};

const severities: Severity[] = ['info', 'warning', 'error', 'critical'];
export function severityRank(s: Severity): number { return severities.indexOf(s); }

const token = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const mutationLike = /(?:^|\/)(?:call|create|delete|execute|invoke|mutate|run|set|start|stop|update|write)(?:$|\/)/i;

function validateProfile(p: McpProfile, seen: Set<string>): void {
  if (!p || typeof p !== 'object') throw new Error('mcpProfiles entries must be objects');
  if (typeof p.name !== 'string' || !/^[A-Za-z0-9._-]{1,64}$/.test(p.name)) throw new Error('MCP profile name must match [A-Za-z0-9._-]{1,64}');
  if (seen.has(p.name)) throw new Error(`duplicate MCP profile name ${p.name}`);
  seen.add(p.name);
  if (!p.clientCapabilities || typeof p.clientCapabilities !== 'object' || Array.isArray(p.clientCapabilities)) throw new Error(`MCP profile ${p.name} clientCapabilities must be an object`);
  if (p.headersFromEnv) {
    for (const [header, envName] of Object.entries(p.headersFromEnv)) {
      if (!token.test(header) || /^(?:host|content-length|mcp-protocol-version|mcp-method|mcp-name)$/i.test(header)) throw new Error(`MCP profile ${p.name} has forbidden header ${header}`);
      if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(envName)) throw new Error(`MCP profile ${p.name} has invalid environment variable name ${envName}`);
    }
  }
}

function validateExtensionProbe(p: McpExtensionProbe): void {
  if (!p || p.readOnly !== true) throw new Error('MCP extension probes must explicitly set readOnly=true');
  if (typeof p.method !== 'string' || !p.method.includes('/')) throw new Error('MCP extension probe method must be a namespaced RPC method');
  if (p.method === 'tools/call' || mutationLike.test(p.method)) throw new Error(`MCP extension probe method is not safely read-only: ${p.method}`);
}

export function mergePolicy(partial: Partial<Policy> = {}): Policy {
  const alias = partial.inspectMcpTools;
  const explicitPrimitives = partial.inspectMcpPrimitives;
  const p: Policy = {
    ...DEFAULT_POLICY,
    ...partial,
    ...(explicitPrimitives === undefined && typeof alias === 'boolean' ? { inspectMcpPrimitives: alias } : {}),
    mcpProfiles: partial.mcpProfiles ? structuredClone(partial.mcpProfiles) : structuredClone(DEFAULT_POLICY.mcpProfiles),
    mcpPromptProbes: partial.mcpPromptProbes ? structuredClone(partial.mcpPromptProbes) : [],
    mcpResourceProbes: partial.mcpResourceProbes ? structuredClone(partial.mcpResourceProbes) : [],
    mcpExtensionProbes: partial.mcpExtensionProbes ? structuredClone(partial.mcpExtensionProbes) : [],
    allowedPorts: partial.allowedPorts ? [...partial.allowedPorts] : [...DEFAULT_POLICY.allowedPorts],
    allowedTrustAlgorithms: partial.allowedTrustAlgorithms ? [...partial.allowedTrustAlgorithms] : [...DEFAULT_POLICY.allowedTrustAlgorithms]
  };
  delete p.inspectMcpTools;

  if (!Number.isInteger(p.maxDepth) || p.maxDepth < 0 || p.maxDepth > 16) throw new Error('maxDepth must be 0..16');
  if (!Number.isInteger(p.maxCatalogs) || p.maxCatalogs < 1 || p.maxCatalogs > 1000) throw new Error('maxCatalogs must be 1..1000');
  if (!Number.isInteger(p.maxEntriesPerCatalog) || p.maxEntriesPerCatalog < 1 || p.maxEntriesPerCatalog > 100000) throw new Error('maxEntriesPerCatalog must be 1..100000');
  if (!Number.isInteger(p.maxResponseBytes) || p.maxResponseBytes < 1024) throw new Error('maxResponseBytes must be at least 1024');
  if (!Number.isInteger(p.timeoutMs) || p.timeoutMs < 100) throw new Error('timeoutMs must be at least 100');
  if (!Number.isInteger(p.maxRedirects) || p.maxRedirects < 0 || p.maxRedirects > 10) throw new Error('maxRedirects must be 0..10');
  if (!Array.isArray(p.allowedPorts) || p.allowedPorts.length === 0 || p.allowedPorts.some(x => !Number.isInteger(x) || x < 1 || x > 65535)) throw new Error('allowedPorts contains invalid port');
  if (!Number.isInteger(p.maxMcpPages) || p.maxMcpPages < 1 || p.maxMcpPages > 1000) throw new Error('maxMcpPages must be 1..1000');
  if (!Number.isInteger(p.maxMcpItems) || p.maxMcpItems < 1 || p.maxMcpItems > 100000) throw new Error('maxMcpItems must be 1..100000');
  if (typeof p.mcpProtocolVersion !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(p.mcpProtocolVersion)) throw new Error('mcpProtocolVersion must be YYYY-MM-DD');
  if (!Array.isArray(p.mcpProfiles) || p.mcpProfiles.length < 1 || p.mcpProfiles.length > 64) throw new Error('mcpProfiles must contain 1..64 profiles');
  const seen = new Set<string>();
  for (const profile of p.mcpProfiles) validateProfile(profile, seen);
  if (!Array.isArray(p.mcpPromptProbes) || !Array.isArray(p.mcpResourceProbes) || !Array.isArray(p.mcpExtensionProbes)) throw new Error('MCP probes must be arrays');
  for (const probe of p.mcpPromptProbes) if (!probe || typeof probe.name !== 'string' || !probe.name) throw new Error('MCP prompt probes require name');
  for (const probe of p.mcpResourceProbes) if (!probe || typeof probe.uri !== 'string' || !probe.uri) throw new Error('MCP resource probes require uri');
  for (const probe of p.mcpExtensionProbes) validateExtensionProbe(probe);
  if (!Number.isInteger(p.maxTrustEvidenceBytes) || p.maxTrustEvidenceBytes < 1024 || p.maxTrustEvidenceBytes > 100_000_000) throw new Error('maxTrustEvidenceBytes must be 1024..100000000');
  if (!Array.isArray(p.allowedTrustAlgorithms) || p.allowedTrustAlgorithms.some(a => typeof a !== 'string' || !a)) throw new Error('allowedTrustAlgorithms must be an array of strings');
  if (!severities.includes(p.failOn)) throw new Error('invalid failOn severity');
  return p;
}

export function policyFingerprint(policy: Policy): string { return sha256(canonicalJson(policy)); }
