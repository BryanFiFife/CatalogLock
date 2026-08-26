# Security policy

CatalogLock is a security-sensitive resolver. Please do not file exploitable SSRF, DNS-rebinding, parser-confusion, trust-bypass, or lockfile-integrity findings as public issues before a fix is available.

Report vulnerabilities privately through GitHub Security Advisories for the repository when available. Include a minimal reproduction, affected version, impact, and any proposed mitigation.

## Security boundaries

CatalogLock treats discovery metadata as untrusted. It does not treat an ARD trust-manifest attestation string as proof that an audit or certification is genuine. Optional signatures are recorded but are not considered cryptographically verified unless a future verifier explicitly validates them against a supported identity method.
