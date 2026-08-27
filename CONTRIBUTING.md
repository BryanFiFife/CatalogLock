# Contributing

1. Fork the repository and create a focused branch.
2. Add or update tests for every behavior change.
3. Run `npm ci && npm run check && npm audit --audit-level=high`.
4. For resolver or MCP-introspection changes, include adversarial tests covering private IPs, redirects, recursion, pagination, tool drift and authority confusion.
5. Do not weaken a security invariant merely to accept a catalog or server.

Small, reviewable pull requests are preferred.
