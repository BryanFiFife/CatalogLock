<div align="center">

# 🔒 CatalogLock

### **Lock the agentic supply chain before your agent connects to it.**

[![CI](https://github.com/BryanFiFife/CatalogLock/actions/workflows/ci.yml/badge.svg)](https://github.com/BryanFiFife/CatalogLock/actions/workflows/ci.yml)
[![Node 20+](https://img.shields.io/badge/node-%3E%3D20-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-7c3aed)](LICENSE)
[![Runtime deps](https://img.shields.io/badge/runtime%20dependencies-0-00b894)](#security-model)
[![ARD](https://img.shields.io/badge/ARD-v0.9%20draft-4f46e5)](https://agenticresourcediscovery.org/spec/)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-2563eb)](#outputs)

**ARD / ai-catalog security · recursive resolution · SSRF resistance · trust graph · deterministic lockfile · blast-radius diff · SARIF · GitHub Action**

</div>

---

Agentic Resource Discovery (ARD) is creating a web-scale way for agents to discover MCP servers, A2A agents, skills and APIs. Discovery is powerful precisely because catalogs are **remote, recursive and machine-consumed**. That also makes the catalog graph a supply-chain boundary.

**CatalogLock is the missing pre-connect gate.** It resolves an ARD catalog graph under strict network limits, checks whether identifiers and trust identities line up with the domains claiming them, freezes the reviewed graph into a deterministic lockfile, and tells CI exactly what changed later.

> `retrieval ≠ trust` and `discovery ≠ authorization`.

## Why this exists

A catalog entry can look harmless while changing the authority your agent ultimately reaches. A nested catalog can point at internal infrastructure. A publisher identifier can claim one domain while being served by another. An attestation can simply be a string. A dependency can quietly drift between reviews.

CatalogLock turns those possibilities into explicit, reviewable findings.

```text
open web
   │
   ▼
/.well-known/ai-catalog.json
   │
   ▼
┌──────────────────────────────┐
│          CatalogLock         │
│  URL gate + DNS pinning      │
│  bounded recursive resolver  │
│  schema + authority checks   │
│  trust graph                 │
│  deterministic lockfile      │
└──────────────┬───────────────┘
               │
        ┌──────┴──────┐
        ▼             ▼
      allow         fail CI
        │
        ▼
 MCP / A2A / API client
```

## 30-second start

```bash
npm install -g cataloglock

# Scan a publisher. CatalogLock uses the canonical ARD path:
cataloglock scan example.com

# Freeze the reviewed graph:
cataloglock lock example.com --output cataloglock.lock.json

# On the next change:
cataloglock lock example.com --output cataloglock.next.json
cataloglock diff cataloglock.lock.json cataloglock.next.json
```

Until an npm package is published, run directly from the repository:

```bash
npm ci
npm run build
node dist/cli.cjs scan example.com
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
| **Signatures** | Presence is surfaced; cryptographic verification is intentionally not claimed in v0.1 |
| **Drift** | Lockfile comparison classifies resource, catalog and authority changes |

## Deterministic lockfiles

`cataloglock lock` writes a stable JSON file with no timestamp noise. It includes:

- SHA-256 of every fetched catalog body
- a SHA-256 fingerprint of the effective policy
- a canonical graph digest
- normalized resource definitions
- publisher and trust score
- signature-presence state
- findings that existed at lock time

The same graph plus the same policy produces the same lockfile bytes.

## Blast-radius diff

A normal version change is not equivalent to an authority change. CatalogLock separates them:

```text
[WARNING] resource-added: Resource added: urn:air:example.com:agent:planner
[ERROR]   resource-changed: Resource definition changed: urn:air:example.com:mcp:files
[CRITICAL] authority-changed: Trust/authority changed for urn:air:example.com:agent:payments
```

The diff summary counts added/removed catalogs, resources, ordinary resource mutations and **authority changes**.

## Outputs

```bash
cataloglock scan example.com --format json
cataloglock scan example.com --format html --output cataloglock-report.html
cataloglock scan example.com --format sarif --output cataloglock.sarif
```

The HTML report is self-contained. SARIF 2.1.0 can be uploaded to code-scanning systems.

## GitHub Action

Until a semver tag is published, pin the immutable release commit:

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
      - uses: BryanFiFife/CatalogLock@970212dfd7bba67a822c0058ccca8b43d1533fe4
        with:
          target: example.com
          fail-on: error
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: cataloglock.sarif
```

## Poisoned demo

`examples/poisoned-catalog.json` deliberately combines two classes of bad discovery metadata:

1. a resource whose `urn:air` publisher claims `example.com` but whose URL and trust identity point to an attacker domain;
2. a nested catalog targeting the cloud metadata link-local address.

It exists so security behavior can be demonstrated and regression-tested without relying on live malicious infrastructure.

## Security model

CatalogLock has **zero runtime npm dependencies**. The network resolver is built on Node core so the most sensitive boundary stays small and auditable.

The resolver is fail-closed. It does not equate a catalog's `SOC2-Type2`, `HIPAA`, `GDPR` or similar text with verified compliance. It does not claim that a present signature is valid. It does not authorize an MCP server or A2A agent merely because discovery metadata passed.

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) and [SECURITY.md](SECURITY.md).

## ARD compatibility

CatalogLock tracks the standards-track ARD specification. As of v0.9 draft, publishers expose a static catalog at:

```text
https://{domain}/.well-known/ai-catalog.json
```

`/.well-known/ard.json` is supported only as a compatibility probe for early implementations and generates a warning when used.

## Commands

```text
cataloglock scan <target>      resolve + assess + report
cataloglock lock <target>      produce deterministic lockfile
cataloglock diff <old> <new>   calculate blast radius
cataloglock verify <target>    resolve live graph and compare to an existing lock
cataloglock version            print version
```

Exit codes: `0` clean, `1` tool/runtime failure, `2` policy finding threshold reached, `3` lock drift detected.

## Roadmap

- cryptographic verification for supported JWS / DID Web trust manifests
- redirect-chain policy controls and audit telemetry
- optional public-suffix-aware organization-boundary policy
- signed lockfiles and transparency-log anchoring
- registry ingestion mode for fleet-scale scanning
- policy packs for enterprise MCP/A2A environments

## Contributing

Security pull requests are welcome. Resolver changes should arrive with adversarial tests. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0.

---

<div align="center">

**The open agentic web needs a lockfile.**

⭐ Star the repo if you want discovery to become reviewable infrastructure instead of blind runtime trust.

</div>
