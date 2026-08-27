<div align="center">

# 🔒 CatalogLock

### **Pin what an agent can discover, trust, and consume before it connects.**

[![CI](https://github.com/BryanFiFife/CatalogLock/actions/workflows/ci.yml/badge.svg)](https://github.com/BryanFiFife/CatalogLock/actions/workflows/ci.yml)
[![Conformance](https://img.shields.io/badge/conformance-v0.3.0%20ARD%20%2B%20MCP%20passed-00b894)](https://github.com/BryanFiFife/CatalogLock/releases/tag/v0.3.0)
[![Release](https://img.shields.io/github/v/release/BryanFiFife/CatalogLock?display_name=tag&sort=semver)](https://github.com/BryanFiFife/CatalogLock/releases/latest)
[![Node](https://img.shields.io/badge/node-20%20%7C%2022%20%7C%2024-339933?logo=node.js&logoColor=white)](https://nodejs.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-7c3aed)](LICENSE)
[![Runtime deps](https://img.shields.io/badge/runtime%20dependencies-0-00b894)](#security-model)
[![Tests](https://img.shields.io/badge/tests-135%2F135%20passing-00b894)](#verification)
[![Lockfile](https://img.shields.io/badge/lockfile-v3-6d5dfc)](#deterministic-lockfiles)
[![ARD](https://img.shields.io/badge/ARD-v0.91-4f46e5)](https://agenticresourcediscovery.org/spec/)
[![MCP](https://img.shields.io/badge/MCP-2026--07--28-2563eb)](https://modelcontextprotocol.io/)
[![Trust](https://img.shields.io/badge/trust-evidence%20verified-00b894)](#trust-and-provenance)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-2563eb)](#outputs)

**Stable identity is not stable capability. Stable capability is not stable implementation. CatalogLock makes each distinction explicit.**

</div>

---

CatalogLock is a deterministic pre-connect security gate for Agentic Resource Discovery (ARD) and Model Context Protocol (MCP) infrastructure. It resolves ARD entry sources under a strict outbound-network policy, assesses authority and trust evidence, snapshots MCP protocol surfaces under explicit client/authentication profiles, and freezes the reviewed state into a lockfile that CI can diff later.

CatalogLock does **not** execute discovered tools and does **not** claim that metadata, schemas, signatures, attestations, or provenance prove runtime behavior. It records and verifies what can be verified, and keeps the remaining uncertainty visible.

## What v0.3.0 locks

### ARD v0.91

- `/.well-known/ard.json` is the canonical publisher path.
- `/.well-known/ai-catalog.json` is supported only as an explicit predecessor fallback.
- HTML `rel="ard"` discovery is supported.
- ARD v0.91 entry manifests, value-or-reference delivery, `urn:air` identifiers and JSON-LD extension context are validated.
- recursive entry sources are bounded by depth and count.
- identifier collisions across entry sources are critical.

### MCP 2026-07-28

> **Published SDK compatibility boundary:** the npm-published `@modelcontextprotocol/server@2.0.0` package currently advertises protocol support only through `2025-11-25`. CatalogLock therefore does not claim that package as a 2026-07-28 peer. Release gating uses the current official SDK source pinned by commit for positive 2026-07-28 interoperability, and separately verifies that older published peers fail closed with an accurate protocol-version diagnostic.

For every concrete Streamable HTTP remote and every configured scan profile, CatalogLock can lock:

- `server/discover`
  - supported protocol versions
  - server capabilities
  - extension declarations
  - server instructions
  - server identity metadata
  - cache hints
- `tools/list`
- `prompts/list`
- `resources/list`
- `resources/templates/list`
- optional `prompts/get` content probes
- optional `resources/read` content probes
- explicit custom **read-only** extension probes

Every modern MCP request carries the 2026-07-28 per-request envelope and required Streamable HTTP routing headers. Results are checked for JSON-RPC identity, `resultType`, modern cache hints where required, pagination safety and deterministic item identity.

`tools/call` is deliberately forbidden as a CatalogLock probe.

## The drift case that matters

Reviewed state:

```text
get_invoice
search_invoices
```

Later, with the same publisher, identifier, Server Card and endpoint:

```text
get_invoice
search_invoices
delete_invoice
```

CatalogLock classifies that as critical drift:

```text
[CRITICAL] mcp-tool-added:
New executable/consumable MCP tool appeared: delete_invoice
```

The same treatment applies to changed tool schemas, newly appearing prompts/resources/templates, endpoint drift, capability/extension drift, cache-scope widening and configured read-only content probes.

## Contextual surfaces

MCP surfaces can differ by authentication scope, tenant or declared client capability. CatalogLock therefore treats the client context as part of the lock.

```json
{
  "mcpProfiles": [
    {
      "name": "public",
      "clientCapabilities": {}
    },
    {
      "name": "finance-admin",
      "clientCapabilities": { "sampling": {} },
      "headersFromEnv": {
        "Authorization": "MCP_FINANCE_TOKEN"
      }
    }
  ]
}
```

Only the **environment-variable name** enters policy/lock hashing. The credential value is injected at runtime and is never persisted in CatalogLock findings, lockfiles or reports.

## Trust and provenance

CatalogLock separates trust evidence into explicit states:

- `absent`
- `verified`
- `present-unverified`
- `unsupported`
- `invalid`

Built-in verification includes:

- authority-aligned HTTPS / `did:web` / SPIFFE identity checks
- SHA-256 verification for remote attestation/provenance evidence
- canonical detached/compact JWS verification when the trust framework explicitly declares the CatalogLock canonical-JWS method
- authority-resolved JWKS or `did:web` verification keys
- pluggable trust-framework verifiers for formats the core intentionally does not pretend to understand

`requireVerifiedTrust` converts unresolved declared evidence into a policy failure.

Implementation provenance can reduce the gap between declared capability and deployed code, but CatalogLock does not make the false claim that a digest or attestation proves runtime behavior. It proves only the evidence relationship it actually verifies.

## Deterministic lockfiles

Lockfile v3 covers:

- ARD context and root entry source
- raw entry-source body digests
- normalized resource definitions
- policy fingerprint
- authority/trust state and verified evidence digest
- Server Card digest
- stable remote index and endpoint
- scan profile
- `server/discover` surface
- tools, prompts, resources and templates
- cache policy
- optional read-only/content probes
- complete surface and graph digests

No timestamps are included, so equivalent state produces equivalent lockfile bytes.

## Network boundary

All ARD, Server Card, trust-evidence and MCP HTTP requests pass through the same outbound policy:

- HTTPS by default
- port allowlist
- DNS resolution before connect
- rejection of loopback, RFC1918, link-local, carrier-grade NAT, documentation, multicast and reserved ranges
- socket lookup pinned to an already-vetted address
- response-size ceiling
- timeout ceiling
- redirect ceiling
- POST redirects restricted to 307/308
- embedded URL credentials forbidden

## 30-second start

```bash
npm ci
npm run build
node dist/cli.cjs scan example.com
node dist/cli.cjs lock example.com --output cataloglock.lock.json
node dist/cli.cjs verify example.com --lock cataloglock.lock.json
```

## GitHub Action

```yaml
- uses: BryanFiFife/CatalogLock@v0.3.0
  with:
    target: example.com
    fail-on: error
    inspect-mcp-primitives: "true"
    inspect-mcp-discover: "true"
```

The v0.2 `inspect-mcp-tools` input remains as a compatibility alias.

## Commands

```text
cataloglock scan <target>
cataloglock lock <target>
cataloglock diff <old.lock.json> <new.lock.json>
cataloglock verify <target> --lock cataloglock.lock.json
cataloglock version
```

Important switches:

```text
--no-mcp-primitives
--no-mcp-tools             deprecated compatibility alias
--no-mcp-discover
--mcp-profile NAME[,NAME]
--require-mcp-inspection
--require-verified-trust
```

Exit codes: `0` clean, `1` runtime/tooling failure, `2` policy threshold reached, `3` lock drift detected.

## Outputs

```bash
cataloglock scan example.com --format json
cataloglock scan example.com --format html --output cataloglock-report.html
cataloglock scan example.com --format sarif --output cataloglock.sarif
```

The HTML report is self-contained. SARIF output is SARIF 2.1.0.

## Security model

CatalogLock has **zero runtime npm dependencies**. Node core handles the security-sensitive network and cryptographic primitives.

It deliberately does not:

- execute discovered MCP tools
- treat discovery as authorization
- claim an unverified signature is proof
- infer compliance from labels such as SOC 2, HIPAA or GDPR
- claim that an unchanged schema means unchanged implementation behavior
- persist authentication secret values
- silently ignore uninspectable required MCP surfaces when fail-closed policy is enabled

See [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md), [docs/POLICY.md](docs/POLICY.md) and [SECURITY.md](SECURITY.md).

## Verification

The v0.3.0 release gate includes:

- 135 adversarial/unit/end-to-end tests
- Node 20, 22 and 24
- TypeScript typecheck
- production build reproducibility
- package-content leak inspection
- tracked-tree leak inspection
- `npm audit --audit-level=high`
- official ARD v0.91 conformance CLI against the shipped good example
- positive MCP 2026-07-28 interoperability against the current official TypeScript SDK source pinned to an immutable upstream commit, plus an explicit published-SDK compatibility-boundary check
- release-asset SHA-256 verification after publication

## License

Apache-2.0.
