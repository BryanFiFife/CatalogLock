<div align="center">

# 🔒 CatalogLock

### **Lock the agentic supply chain before your agent connects to it.**

[![CI](https://github.com/BryanFiFife/CatalogLock/actions/workflows/ci.yml/badge.svg)](https://github.com/BryanFiFife/CatalogLock/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/BryanFiFife/CatalogLock?display_name=tag&sort=semver)](https://github.com/BryanFiFife/CatalogLock/releases/latest)
[![Node 20+](https://img.shields.io/badge/node-%3E%3D20-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-7c3aed)](LICENSE)
[![Runtime deps](https://img.shields.io/badge/runtime%20dependencies-0-00b894)](#security-model)
[![Tests](https://img.shields.io/badge/tests-54%2F54%20passing-00b894)](#security-model)
[![Lockfile](https://img.shields.io/badge/lockfile-v2-6d5dfc)](#deterministic-lockfiles)
[![ARD](https://img.shields.io/badge/ARD-v0.91%20proposal-4f46e5)](https://agenticresourcediscovery.org/spec/)
[![MCP](https://img.shields.io/badge/MCP-2026--07--28-2563eb)](https://modelcontextprotocol.io/)
[![Tool drift](https://img.shields.io/badge/MCP%20tool%20drift-locked-e11d48)](#live-mcp-tool-surface-locking)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-2563eb)](#outputs)

**ARD / ai-catalog security · recursive resolution · SSRF resistance · trust graph · deterministic lockfile · live MCP `tools/list` locking · blast-radius diff · SARIF · GitHub Action**

</div>

---

Agentic Resource Discovery (ARD) gives agents a web-scale discovery layer for MCP servers, A2A agents, skills and APIs. Discovery is powerful precisely because catalogs are **remote, recursive and machine-consumed**. That also makes the catalog graph a supply-chain boundary.

**CatalogLock is the pre-connect gate.** It resolves an ARD catalog graph under strict network limits, checks whether identifiers and trust identities line up with the domains claiming them, freezes the reviewed graph into a deterministic lockfile, and now goes one layer deeper for MCP: it can lock the **actual runtime tool surface** returned by `tools/list`.

> `retrieval ≠ trust`, `discovery ≠ authorization`, and `stable identity ≠ stable capability`.

## Why this exists

A catalog entry can look harmless while changing the authority your agent ultimately reaches. A nested catalog can point at internal infrastructure. A publisher identifier can claim one domain while being served by another. A dependency can quietly drift between reviews.

And even when all of that stays identical, an MCP server can keep the same identity and endpoint while a new executable tool quietly appears.

CatalogLock v0.2 turns that exact failure mode into an explicit, reviewable diff.

```text
open web
   │
   ▼
/.well-known/ai-catalog.json
   │
   ▼
┌────────────────────────────────────┐
│             CatalogLock            │
│  URL gate + DNS pinning            │
│  bounded recursive resolver        │
│  schema + authority checks         │
│  MCP Server Card resolution        │
│  live tools/list surface snapshot  │
│  deterministic lockfile            │
└─────────────────┬──────────────────┘
                  │
           ┌──────┴──────┐
           ▼             ▼
         allow         fail CI
           │
           ▼
      MCP / A2A / API
```

## 30-second start

```bash
npm install -g cataloglock

cataloglock scan example.com
cataloglock lock example.com --output cataloglock.lock.json

# Later:
cataloglock verify example.com --lock cataloglock.lock.json
```

Until an npm package is published, run directly from the repository:

```bash
npm ci
npm run build
node dist/cli.cjs scan example.com
```

## Live MCP tool-surface locking

ARD and MCP Server Cards intentionally stop before runtime primitive enumeration. A Server Card tells a client **where** the MCP server is; it does not enumerate the tools the server exposes.

CatalogLock v0.2 follows public `application/mcp-server-card+json` entries to their Streamable HTTP endpoint and requests MCP `tools/list` using protocol revision `2026-07-28`.

For every tool it records:

- the tool name
- SHA-256 of the entire canonical tool definition
- SHA-256 of `inputSchema`, when present
- SHA-256 of `outputSchema`, when present

The complete sorted tool surface gets its own digest too.

That means this drift:

```text
yesterday
  search_documents
  get_invoice

today
  search_documents
  get_invoice
  delete_invoice
```

becomes:

```text
[CRITICAL] mcp-tool-added:
New executable MCP tool appeared: delete_invoice on urn:air:example.com:mcp:billing
```

The server can keep the same publisher, identifier, Server Card, URL and TLS identity. The new capability still appears in the lockfile diff.

Tool definition/schema mutations are also `critical`. Removed tools are surfaced as warnings. Endpoint changes are `critical`.

### Authenticated MCP servers

CatalogLock never writes credentials into a lockfile. If a Server Card declares required authentication, or a public `tools/list` cannot be inspected, v0.2 records a warning and leaves that surface unlocked.

For environments where incomplete MCP inspection is unacceptable:

```json
{
  "requireMcpInspection": true
}
```

That turns non-inspectable MCP surfaces into policy errors.

Disable live inspection explicitly with:

```bash
cataloglock lock example.com --no-mcp-tools
```

## What it checks

| Boundary | CatalogLock behavior |
|---|---|
| **Catalog location** | Uses `/.well-known/ai-catalog.json`; optionally probes early `ard.json` experiments only after canonical 404 |
| **Transport** | HTTPS by default, port allowlist, response-byte and timeout ceilings |
| **SSRF** | Rejects loopback, RFC1918, link-local, carrier-grade NAT, documentation, multicast and reserved ranges |
| **DNS rebinding** | Resolves first, validates every returned address, then pins the socket lookup to a vetted address |
| **Recursion** | Explicit catalog-count and depth bounds, cycle de-duplication |
| **Schema** | Required catalog/entry fields, URL/data XOR, duplicate identifiers, HTTPS entry URLs |
| **Authority** | `urn:air:<publisher>:...` must align with the catalog source host |
| **Trust identity** | HTTPS, SPIFFE and `did:web` identities are checked against publisher authority |
| **Attestations** | Recorded as claims, never silently promoted into proof |
| **Signatures** | Presence is surfaced; cryptographic verification is intentionally not claimed |
| **Catalog drift** | Lockfile comparison classifies resource, catalog and authority changes |
| **MCP Server Cards** | Resolves current `application/mcp-server-card+json` resources without trusting them as execution proof |
| **MCP endpoint** | Streamable HTTP endpoint changes are critical drift |
| **MCP tools** | New tools and changed tool definitions/schemas are critical drift |
| **MCP pagination** | Bounded page/tool counts, duplicate-name rejection and repeated-cursor detection |

## Deterministic lockfiles

`cataloglock lock` writes stable JSON with no timestamp noise. Lockfile v2 includes:

- SHA-256 of every fetched catalog body
- SHA-256 fingerprint of the effective policy
- a canonical graph digest
- normalized resource definitions
- publisher and trust score
- signature-presence state
- MCP Server Card digest
- MCP endpoint
- canonical runtime tool hashes and schema hashes
- findings that existed at lock time

The same graph, runtime tool surface and policy produce the same lockfile bytes.

## Blast-radius diff

CatalogLock separates ordinary metadata drift from capability and authority drift:

```text
[WARNING]  resource-added: Resource added: urn:air:example.com:agent:planner
[ERROR]    resource-changed: Resource definition changed: urn:air:example.com:mcp:files
[CRITICAL] authority-changed: Trust/authority changed for urn:air:example.com:agent:payments
[CRITICAL] mcp-tool-added: New executable MCP tool appeared: delete_file on urn:air:example.com:mcp:files
[CRITICAL] mcp-tool-changed: MCP tool definition/schema changed: transfer_funds on urn:air:example.com:mcp:payments
```

The blast-radius summary counts catalog, resource, authority, endpoint and MCP tool-surface mutations separately.

## Outputs

```bash
cataloglock scan example.com --format json
cataloglock scan example.com --format html --output cataloglock-report.html
cataloglock scan example.com --format sarif --output cataloglock.sarif
```

The HTML report is self-contained. SARIF 2.1.0 can be uploaded to code-scanning systems.

## GitHub Action

```yaml
name: Catalog security
on: [push, pull_request]

jobs:
  cataloglock:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - uses: BryanFiFife/CatalogLock@v0.2.0
        with:
          target: example.com
          fail-on: error
          inspect-mcp-tools: "true"
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: cataloglock.sarif
```

## Security model

CatalogLock has **zero runtime npm dependencies**. The network resolver and MCP HTTP requester use Node core so the most sensitive boundary stays small and auditable.

Every Server Card URL and MCP endpoint passes through the same outbound URL policy, DNS resolution, public-IP validation and socket pinning used for catalog retrieval. POST redirects are only followed for 307/308, preventing method-changing redirect surprises.

The resolver remains fail-closed. It does not equate `SOC2-Type2`, `HIPAA`, `GDPR` or similar strings with verified compliance. It does not claim that a present signature is valid. It does not execute discovered tools and does not authorize an MCP server merely because discovery metadata or a `tools/list` snapshot passed.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [docs/POLICY.md](docs/POLICY.md).

## ARD compatibility

CatalogLock tracks the current ARD proposal, including domain-anchored `urn:air` identifiers and `application/mcp-server-card+json` entries. The README badge tracks ARD v0.91 as published on 26 August 2026.

`/.well-known/ard.json` remains a compatibility probe for early implementations and generates a warning when used.

## Commands

```text
cataloglock scan <target>      resolve + assess + inspect MCP + report
cataloglock lock <target>      produce deterministic lockfile v2
cataloglock diff <old> <new>   calculate blast radius
cataloglock verify <target>    resolve live graph/tool surface and compare to a lock
cataloglock version            print version
```

Exit codes: `0` clean, `1` tool/runtime failure, `2` policy finding threshold reached, `3` lock drift detected.

## Roadmap

- authenticated MCP inspection without ever persisting secret material
- cryptographic verification for supported JWS / DID Web trust manifests
- signed lockfiles and transparency-log anchoring
- registry ingestion mode for fleet-scale scanning
- policy packs for enterprise MCP/A2A environments

## Contributing

Security pull requests are welcome. Resolver and MCP-introspection changes should arrive with adversarial tests. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0.

---

<div align="center">

**Stable identity is not stable capability. Lock both.**

⭐ Star the repo if you want agent discovery to become reviewable infrastructure instead of blind runtime trust.

</div>
