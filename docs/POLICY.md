# Policy reference

The default policy is deliberately conservative for public-web discovery.

| Field | Default | Meaning |
|---|---:|---|
| `maxDepth` | 4 | Maximum nested catalog depth |
| `maxCatalogs` | 32 | Maximum unique catalogs in one resolution graph |
| `maxEntriesPerCatalog` | 5000 | Per-catalog entry ceiling |
| `maxResponseBytes` | 2,000,000 | Maximum catalog response body |
| `timeoutMs` | 8000 | Per-request timeout |
| `maxRedirects` | 3 | Maximum redirect hops; every hop is URL-validated, DNS-checked and socket-pinned |
| `allowedPorts` | `[443]` | Outbound catalog ports |
| `allowHttp` | `false` | Permit cleartext HTTP |
| `allowCompatibilityArdJson` | `true` | Probe `ard.json` only after canonical path returns 404 |
| `requirePublisherMatch` | `true` | Publisher/source alignment policy |
| `requireHttpsEntries` | `true` | Resource URL HTTPS requirement |
| `failOn` | `error` | CI threshold |

`/.well-known/ai-catalog.json` is the current standards-track ARD publisher path. The `ard.json` probe exists only for compatibility with early experiments.
