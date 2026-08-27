# Threat model

CatalogLock protects the point where an AI system turns open-web discovery into a set of callable capabilities.

## Threats

- SSRF through nested catalogs, Server Cards or MCP endpoint URLs
- DNS rebinding between validation and connection
- redirect-to-private-network pivots
- oversized or cyclic catalog graphs
- publisher/URN authority confusion
- trust-manifest identity laundering
- silent resource drift after review
- silent MCP tool additions or schema mutations while server identity remains stable
- malicious or accidental `tools/list` pagination loops
- dependency or catalog substitution in CI
- misleading compliance-attestation strings

## Controls

- HTTPS and port allowlists
- public-IP validation for every outbound request
- DNS pinning for the actual socket lookup
- explicit recursion, graph, byte, MCP page and tool-count bounds
- domain-anchored `urn:air:` checks
- identity-to-publisher checks for HTTPS, SPIFFE and DID Web identifiers
- deterministic lockfiles with SHA-256 catalog, Server Card, tool-definition and graph digests
- full canonical MCP tool hashes plus separate input/output schema hashes
- critical classification for newly appearing MCP tools and changed tool definitions
- blast-radius diffs
- SARIF/HTML/JSON outputs and CI policy gating

## MCP tool-surface model

MCP Server Cards deliberately do not enumerate runtime primitives. CatalogLock follows a discovered public Server Card to its Streamable HTTP endpoint and requests `tools/list` using MCP `2026-07-28`. Every tool object is canonicalized and hashed, so a newly appearing `delete_*` capability is visible even when the publisher, identifier, Server Card URL and MCP endpoint do not change.

Authenticated or otherwise non-inspectable MCP servers generate a warning by default. `requireMcpInspection: true` makes that condition a policy error.

## Non-goals

CatalogLock does not authenticate or authorize the resource protocol itself and does not execute tools. MCP, A2A or API clients must still perform their own authentication and authorization. CatalogLock also does not currently perform full JWS/DID signature verification; signature presence is evidence to inspect, not proof.
