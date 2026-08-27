# Policy reference

CatalogLock v0.3.0 treats discovery, authority, trust evidence and the MCP client context as separate security boundaries.

| Field | Default | Meaning |
|---|---:|---|
| `maxDepth` | 4 | Maximum nested ARD entry-source depth |
| `maxCatalogs` | 32 | Maximum unique entry sources |
| `maxEntriesPerCatalog` | 5000 | Per-manifest entry ceiling |
| `maxResponseBytes` | 2,000,000 | Maximum normal HTTP response size |
| `timeoutMs` | 8000 | Per-request timeout |
| `maxRedirects` | 3 | Redirect ceiling, with every hop revalidated |
| `allowedPorts` | `[443]` | Outbound port allowlist |
| `allowHttp` | `false` | Permit cleartext HTTP |
| `allowCompatibilityAiCatalogJson` | `true` | Permit predecessor `/.well-known/ai-catalog.json` fallback after canonical ARD resolution fails |
| `requirePublisherMatch` | `true` | Require `urn:air` publisher/source authority alignment |
| `requireHttpsEntries` | `true` | Require HTTPS resource URLs |
| `inspectMcpPrimitives` | `true` | Lock tools, prompts, resources and resource templates |
| `inspectMcpDiscover` | `true` | Lock `server/discover` capability/version/instruction surface |
| `requireMcpInspection` | `false` | Escalate an uninspectable requested MCP context from warning to error |
| `maxMcpPages` | 25 | Maximum pages per MCP list method |
| `maxMcpItems` | 5000 | Maximum unique items per MCP list method |
| `mcpProtocolVersion` | `2026-07-28` | MCP protocol revision used by the scanner |
| `mcpProfiles` | public profile | Client capability/authentication contexts to inspect |
| `mcpPromptProbes` | `[]` | Explicit prompt content probes using `prompts/get` |
| `mcpResourceProbes` | `[]` | Explicit resource content probes using `resources/read` |
| `mcpExtensionProbes` | `[]` | Explicit custom read-only RPC probes; `readOnly:true` is mandatory |
| `requireVerifiedTrust` | `false` | Require trust state `verified` |
| `maxTrustEvidenceBytes` | 2,000,000 | Evidence-response byte ceiling |
| `allowedTrustAlgorithms` | RS256, ES256, EdDSA | Canonical-JWS allowlist |
| `failOn` | `error` | CI finding threshold |

## MCP profiles

Credentials are referenced by environment-variable name only:

```json
{
  "mcpProfiles": [
    {"name":"public","clientCapabilities":{}},
    {
      "name":"finance-admin",
      "clientCapabilities":{"extensions":{"io.modelcontextprotocol/ui":{}}},
      "headersFromEnv":{"Authorization":"MCP_FINANCE_TOKEN"}
    }
  ]
}
```

The environment-variable name participates in the policy fingerprint. The secret value does not enter the policy, lockfile, finding evidence or report.

## Read-only probes

CatalogLock will not execute `tools/call`. Custom extension probes must be namespaced, must declare `readOnly:true`, and mutation-looking method names are rejected by policy validation.
