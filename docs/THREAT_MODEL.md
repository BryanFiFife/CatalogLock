# Threat model

CatalogLock protects the point where an AI system turns an open-web discovery catalog into a set of callable capabilities.

## Threats

- SSRF through nested catalogs or resource URLs
- DNS rebinding between validation and connection
- redirect-to-private-network pivots
- oversized or cyclic catalog graphs
- publisher/URN authority confusion
- trust-manifest identity laundering
- silent capability drift after review
- dependency or catalog substitution in CI
- misleading compliance-attestation strings

## Controls

- HTTPS and port allowlists
- public-IP validation for every outbound catalog request
- DNS pinning for the actual socket lookup
- explicit recursion, graph and byte bounds
- domain-anchored `urn:air:` checks
- identity-to-publisher checks for HTTPS, SPIFFE and DID Web identifiers
- deterministic lockfiles with SHA-256 catalog and graph digests
- blast-radius diffs
- SARIF/HTML/JSON outputs and CI policy gating

## Non-goals

CatalogLock does not authenticate or authorize the resource protocol itself. MCP, A2A or API clients must still perform their own authentication and authorization. CatalogLock also does not currently perform full JWS/DID signature verification; signature presence is evidence to inspect, not proof.
