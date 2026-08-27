# Policy reference

The default policy is deliberately conservative for public-web discovery while enabling live MCP surface locking where the server is publicly inspectable.

| Field | Default | Meaning |
|---|---:|---|
| `maxDepth` | 4 | Maximum nested catalog depth |
| `maxCatalogs` | 32 | Maximum unique catalogs in one resolution graph |
| `maxEntriesPerCatalog` | 5000 | Per-catalog entry ceiling |
| `maxResponseBytes` | 2,000,000 | Maximum catalog, Server Card or MCP response body |
| `timeoutMs` | 8000 | Per-request timeout |
| `maxRedirects` | 3 | Maximum redirect hops; every hop is URL-validated, DNS-checked and socket-pinned |
| `allowedPorts` | `[443]` | Outbound catalog, Server Card and MCP ports |
| `allowHttp` | `false` | Permit cleartext HTTP |
| `allowCompatibilityArdJson` | `true` | Probe `ard.json` only after canonical path returns 404 |
| `requirePublisherMatch` | `true` | Publisher/source alignment policy |
| `requireHttpsEntries` | `true` | Resource URL HTTPS requirement |
| `inspectMcpTools` | `true` | Resolve public MCP Server Cards and snapshot live `tools/list` surfaces |
| `requireMcpInspection` | `false` | Make non-inspectable MCP resources policy errors instead of warnings |
| `maxMcpPages` | 25 | Maximum `tools/list` pagination pages |
| `maxMcpTools` | 5000 | Maximum unique tools per MCP server |
| `mcpProtocolVersion` | `2026-07-28` | MCP protocol revision used for live inspection |
| `failOn` | `error` | CI threshold |

`/.well-known/ai-catalog.json` is the current ARD publisher path. The `ard.json` probe exists only for compatibility with early experiments.

CatalogLock never persists authentication material in a lockfile. If an MCP Server Card declares required authentication, the surface is reported as non-inspectable unless a future authenticated-inspection mechanism is explicitly configured.
