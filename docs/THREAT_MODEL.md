# Threat model

CatalogLock protects the transition from open discovery to an agent-visible protocol surface. It deliberately separates four questions: **what was discovered, who controls it, what evidence was verified, and what the server exposes to this client context.**

## In scope

- SSRF through ARD entry sources, Server Cards, trust evidence or MCP endpoints
- DNS rebinding and redirect pivots to non-public networks
- oversized/deep/cyclic discovery graphs and pagination loops
- `urn:air` publisher/source authority confusion and identifier collisions
- silent resource definition drift
- silent MCP endpoint, capability, extension, instruction or primitive drift
- contextual surfaces that differ by auth scope, tenant or client capabilities
- tool schema mutations, including unsafe `x-mcp-header` annotations
- cache-policy changes, especially private-to-public scope widening
- prompt/resource content drift when explicitly probed
- misleading or unverifiable trust labels
- attestation/provenance digest substitution
- canonical-JWS signature/key substitution for supported trust frameworks
- release contamination by `node_modules`, test output, staging material or secrets

## Controls

- HTTPS/port allowlists, public-IP validation, DNS-pinned sockets and redirect revalidation
- response, timeout, graph, recursion, page, item and schema-complexity bounds
- ARD v0.91-first publisher resolution with predecessor compatibility kept visible
- deterministic ARD context fingerprint and raw entry-source digests
- publisher/resource/identity authority binding
- explicit trust states: absent, present-unverified, unsupported, verified, invalid
- byte-accurate SHA-256 evidence verification
- supported canonical detached/compact JWS verification using JWKS or `did:web`
- pluggable trust-framework verifiers rather than pretending unknown formats are verified
- MCP 2026-07-28 per-request metadata and routing headers
- `server/discover` plus tools/prompts/resources/templates locking per remote/profile
- invalid `x-mcp-header` tools excluded as required by the HTTP transport contract
- authentication values injected from environment only and never persisted
- optional read-only prompt/resource/extension probes; `tools/call` forbidden
- lockfile v3 and critical drift classifications for dangerous surface changes
- tracked-tree/package leak gates and release assets created from the verified Git tree

## Non-goals

CatalogLock does not authorize a discovered service and never executes a discovered tool. It cannot prove that an unchanged remote implementation behaves honestly merely because its declared surface is unchanged. Provenance and signatures prove only the evidence relationship actually verified. Runtime authorization, sandboxing, output validation and service-side security remain separate controls.
