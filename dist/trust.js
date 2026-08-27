import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { canonicalJson, sha256 } from './canonical.js';
export function publisherFromIdentifier(identifier) {
    const m = identifier.match(/^urn:air:([^:]+)(?::[^:]+)+$/i);
    return m?.[1]?.toLowerCase();
}
export function hostWithin(host, publisher) {
    const h = host.toLowerCase().replace(/\.$/, '');
    const p = publisher.toLowerCase().replace(/\.$/, '');
    return h === p || h.endsWith(`.${p}`);
}
export function identityHost(identity) {
    try {
        if (identity.startsWith('did:web:')) {
            const rest = identity.slice('did:web:'.length);
            const first = rest.split(':')[0];
            if (!first)
                return undefined;
            const decoded = decodeURIComponent(first).toLowerCase();
            return decoded.startsWith('[') ? new URL(`https://${decoded}`).hostname.toLowerCase() : decoded.split(':')[0];
        }
        if (identity.startsWith('spiffe://') || identity.startsWith('https://'))
            return new URL(identity).hostname.toLowerCase();
    }
    catch {
        return undefined;
    }
    return undefined;
}
function attestationNames(manifest) {
    if (!Array.isArray(manifest?.attestations))
        return [];
    return manifest.attestations.map(a => typeof a?.type === 'string' ? a.type : '').filter(Boolean).sort();
}
function parseSha256Digest(value) {
    if (typeof value !== 'string')
        return undefined;
    const m = value.trim().match(/^(?:sha256:)?([a-f0-9]{64})$/i);
    return m?.[1]?.toLowerCase();
}
function b64urlDecode(s) {
    if (!/^[A-Za-z0-9_-]*$/.test(s))
        throw new Error('invalid base64url');
    return Buffer.from(s.replace(/-/g, '+').replace(/_/g, '/'), 'base64');
}
function b64urlEncode(v) {
    return Buffer.from(v).toString('base64').replace(/=/g, '').replace(/\+/g, '-').replace(/\//g, '_');
}
function didWebUrl(identity) {
    if (!identity.startsWith('did:web:'))
        return undefined;
    const parts = identity.slice('did:web:'.length).split(':').map(decodeURIComponent);
    const host = parts.shift();
    if (!host)
        return undefined;
    return parts.length ? `https://${host}/${parts.map(encodeURIComponent).join('/')}/did.json` : `https://${host}/.well-known/did.json`;
}
async function fetchJson(url, policy, fetcher) {
    const p = { ...policy, maxResponseBytes: Math.min(policy.maxResponseBytes, policy.maxTrustEvidenceBytes) };
    const r = await fetcher(url, p);
    if (r.status < 200 || r.status >= 300)
        throw new Error(`trust evidence returned HTTP ${r.status}`);
    return JSON.parse(r.body);
}
async function resolveJwks(manifest, policy, fetcher) {
    const schemaJwks = manifest.trustSchema && typeof manifest.trustSchema['jwksUri'] === 'string' ? manifest.trustSchema['jwksUri'] : undefined;
    const jwksUri = typeof manifest.verificationJwksUri === 'string' ? manifest.verificationJwksUri : typeof manifest.jwksUri === 'string' ? manifest.jwksUri : schemaJwks;
    if (jwksUri) {
        const doc = await fetchJson(jwksUri, policy, fetcher);
        if (!doc || typeof doc !== 'object' || !Array.isArray(doc.keys))
            throw new Error('JWKS document is missing keys');
        return doc.keys;
    }
    const didUrl = manifest.identity ? didWebUrl(manifest.identity) : undefined;
    if (didUrl) {
        const doc = await fetchJson(didUrl, policy, fetcher);
        if (!doc || typeof doc !== 'object')
            throw new Error('DID document must be an object');
        const vm = doc.verificationMethod;
        if (!Array.isArray(vm))
            throw new Error('DID document has no verificationMethod array');
        return vm.filter(x => x && typeof x === 'object' && x.publicKeyJwk)
            .map(x => ({ ...x.publicKeyJwk, __id: x.id }));
    }
    return [];
}
function verifyWithJwk(alg, signingInput, signature, jwk) {
    const key = createPublicKey({ key: jwk, format: 'jwk' });
    if (alg === 'RS256')
        return cryptoVerify('RSA-SHA256', signingInput, key, signature);
    if (alg === 'ES256')
        return cryptoVerify('sha256', signingInput, { key, dsaEncoding: 'ieee-p1363' }, signature);
    if (alg === 'EdDSA')
        return cryptoVerify(null, signingInput, key, signature);
    return false;
}
async function verifyCanonicalJws(manifest, policy, fetcher) {
    if (typeof manifest.signature !== 'string' || !manifest.signature)
        return {};
    const methods = Array.isArray(manifest.trustSchema?.verificationMethods) ? manifest.trustSchema.verificationMethods : [];
    const enabled = methods.some(m => /cataloglock(?:-|\/|:)canonical-jws/i.test(m));
    if (!enabled)
        return { reason: 'signature is present but trustSchema does not declare CatalogLock canonical-JWS verification' };
    const parts = manifest.signature.split('.');
    if (parts.length !== 3)
        return { ok: false, reason: 'canonical-JWS signature must use compact JWS serialization' };
    const [protected64, payload64, sig64] = parts;
    let protectedHeader;
    try {
        protectedHeader = JSON.parse(b64urlDecode(protected64).toString('utf8'));
    }
    catch {
        return { ok: false, reason: 'canonical-JWS protected header is invalid' };
    }
    const alg = typeof protectedHeader.alg === 'string' ? protectedHeader.alg : '';
    if (protectedHeader.b64 === false)
        return { ok: false, reason: 'CatalogLock canonical-JWS requires the default base64url payload encoding' };
    if (Array.isArray(protectedHeader.crit) && protectedHeader.crit.some(x => x !== 'b64'))
        return { ok: false, reason: 'canonical-JWS contains unsupported critical protected headers' };
    if (!policy.allowedTrustAlgorithms.includes(alg))
        return { ok: false, reason: `JWS algorithm ${alg || '(missing)'} is not allowed by policy` };
    const unsigned = structuredClone(manifest);
    delete unsigned.signature;
    const canonical = Buffer.from(canonicalJson(unsigned));
    if (payload64 && !b64urlDecode(payload64).equals(canonical))
        return { ok: false, reason: 'embedded JWS payload does not equal canonical trust manifest' };
    const payloadForSigning = payload64 || b64urlEncode(canonical);
    const signingInput = Buffer.from(`${protected64}.${payloadForSigning}`);
    let keys;
    try {
        keys = await resolveJwks(manifest, policy, fetcher);
    }
    catch (e) {
        return { reason: e instanceof Error ? e.message : String(e) };
    }
    if (!keys.length)
        return { reason: 'no verification keys could be resolved for canonical-JWS' };
    const kid = typeof protectedHeader.kid === 'string' ? protectedHeader.kid : undefined;
    if (kid)
        keys = keys.filter(k => k.kid === kid || k.__id === kid);
    if (!keys.length)
        return { ok: false, reason: `no verification key matched kid ${kid}` };
    let sig;
    try {
        sig = b64urlDecode(sig64);
    }
    catch {
        return { ok: false, reason: 'JWS signature is invalid base64url' };
    }
    for (const key of keys) {
        try {
            if (verifyWithJwk(alg, signingInput, sig, key))
                return { ok: true, digest: sha256(canonical) };
        }
        catch {
            continue;
        }
    }
    return { ok: false, reason: 'canonical-JWS signature verification failed' };
}
async function verifyDigestEvidence(manifest, policy, fetcher, findings, location) {
    const verified = [];
    let declaredUnverified = false;
    let invalid = false;
    for (const a of manifest.attestations ?? []) {
        if (!a || typeof a !== 'object')
            continue;
        const expected = parseSha256Digest(a.digest);
        if (!expected || typeof a.uri !== 'string') {
            declaredUnverified = true;
            continue;
        }
        try {
            const p = { ...policy, maxResponseBytes: Math.min(policy.maxResponseBytes, policy.maxTrustEvidenceBytes) };
            const r = await fetcher(a.uri, p);
            if (r.status < 200 || r.status >= 300)
                throw new Error(`HTTP ${r.status}`);
            const actual = sha256(r.bodyBytes ?? Buffer.from(r.body, 'utf8'));
            if (actual !== expected) {
                invalid = true;
                findings.push({ ruleId: 'trust/attestation-digest', severity: 'critical', message: `Attestation digest mismatch for ${a.type ?? a.uri}`, location: a.uri, evidence: { expected, actual } });
            }
            else
                verified.push(`attestation:${expected}`);
        }
        catch (e) {
            declaredUnverified = true;
            findings.push({ ruleId: 'trust/attestation-fetch', severity: 'warning', message: e instanceof Error ? e.message : String(e), location: a.uri });
        }
    }
    for (const p of manifest.provenance ?? []) {
        if (!p || typeof p !== 'object')
            continue;
        const expected = parseSha256Digest(p.sourceDigest);
        if (!expected || typeof p.sourceId !== 'string' || !/^https:\/\//i.test(p.sourceId)) {
            if (p.sourceDigest)
                declaredUnverified = true;
            continue;
        }
        try {
            const fp = { ...policy, maxResponseBytes: Math.min(policy.maxResponseBytes, policy.maxTrustEvidenceBytes) };
            const r = await fetcher(p.sourceId, fp);
            if (r.status < 200 || r.status >= 300)
                throw new Error(`HTTP ${r.status}`);
            const actual = sha256(r.bodyBytes ?? Buffer.from(r.body, 'utf8'));
            if (actual !== expected) {
                invalid = true;
                findings.push({ ruleId: 'trust/provenance-digest', severity: 'critical', message: `Provenance digest mismatch for ${p.sourceId}`, location: p.sourceId, evidence: { expected, actual } });
            }
            else
                verified.push(`provenance:${expected}`);
        }
        catch (e) {
            declaredUnverified = true;
            findings.push({ ruleId: 'trust/provenance-fetch', severity: 'warning', message: e instanceof Error ? e.message : String(e), location: p.sourceId });
        }
    }
    if ((manifest.attestations?.length ?? 0) === 0 && (manifest.provenance?.length ?? 0) === 0 && !manifest.signature)
        declaredUnverified = true;
    return { verified, declaredUnverified, invalid };
}
export async function assessEntryTrust(entry, sourceCatalog, policy, fetcher, verifiers = []) {
    const findings = [];
    const sourceHost = new URL(sourceCatalog).hostname.toLowerCase();
    const publisher = publisherFromIdentifier(entry.identifier);
    const publisherMatchesSource = !!publisher && hostWithin(sourceHost, publisher);
    if (!publisher)
        findings.push({ ruleId: 'authority/identifier', severity: 'error', message: `Identifier is not a domain-anchored urn:air value: ${entry.identifier}`, location: sourceCatalog });
    else if (!publisherMatchesSource && policy.requirePublisherMatch)
        findings.push({ ruleId: 'authority/publisher-source', severity: 'critical', message: `Identifier publisher ${publisher} does not control source host ${sourceHost}`, location: sourceCatalog, evidence: { identifier: entry.identifier } });
    let entryUrlHost;
    let entryUrlWithinPublisher = true;
    if (entry.url) {
        try {
            entryUrlHost = new URL(entry.url).hostname.toLowerCase();
            if (publisher)
                entryUrlWithinPublisher = hostWithin(entryUrlHost, publisher);
            if (publisher && !entryUrlWithinPublisher)
                findings.push({ ruleId: 'authority/resource-host', severity: 'warning', message: `Resource URL host ${entryUrlHost} is outside publisher authority ${publisher}`, location: entry.url });
        }
        catch {
            entryUrlWithinPublisher = false;
        }
    }
    const manifest = entry.trustManifest;
    const identity = typeof manifest?.identity === 'string' ? manifest.identity : undefined;
    let identityMatchesPublisher;
    if (identity && publisher) {
        const host = identityHost(identity);
        identityMatchesPublisher = !!host && hostWithin(host, publisher);
        if (!identityMatchesPublisher)
            findings.push({ ruleId: 'authority/trust-identity', severity: 'critical', message: `Trust identity does not align with publisher ${publisher}`, location: sourceCatalog, evidence: { identity, identifier: entry.identifier } });
    }
    let state = manifest ? 'present-unverified' : 'absent';
    const verifiedEvidenceDigests = [];
    if (manifest) {
        const digestResult = await verifyDigestEvidence(manifest, policy, fetcher, findings, sourceCatalog);
        verifiedEvidenceDigests.push(...digestResult.verified);
        if (digestResult.invalid || identityMatchesPublisher === false)
            state = 'invalid';
        else {
            const jws = await verifyCanonicalJws(manifest, policy, fetcher);
            if (jws.ok === true && jws.digest) {
                verifiedEvidenceDigests.push(`jws:${jws.digest}`);
                state = 'verified';
            }
            else if (jws.ok === false) {
                state = 'invalid';
                findings.push({ ruleId: 'trust/signature-invalid', severity: 'critical', message: jws.reason ?? 'Signature verification failed', location: sourceCatalog, evidence: { identifier: entry.identifier } });
            }
            else if (jws.reason && manifest.signature) {
                state = 'unsupported';
                findings.push({ ruleId: 'trust/signature-unverified', severity: 'warning', message: jws.reason, location: sourceCatalog, evidence: { identifier: entry.identifier } });
            }
            if (digestResult.verified.length > 0 && state !== 'invalid' && state !== 'unsupported')
                state = 'verified';
            else if (digestResult.declaredUnverified && state === 'present-unverified')
                state = 'present-unverified';
        }
        for (const verifier of verifiers) {
            const out = await verifier(manifest, { entry, sourceCatalog, policy, fetcher });
            if (!out)
                continue;
            findings.push(...(out.findings ?? []));
            verifiedEvidenceDigests.push(...(out.verifiedEvidenceDigests ?? []));
            if (out.state === 'invalid')
                state = 'invalid';
            else if (state !== 'invalid' && out.state === 'verified')
                state = 'verified';
            else if (state === 'present-unverified' && out.state === 'unsupported')
                state = 'unsupported';
        }
    }
    if (policy.requireVerifiedTrust && state !== 'verified')
        findings.push({ ruleId: 'trust/required-verification', severity: 'error', message: `Verified trust is required but ${entry.identifier} is ${state}`, location: sourceCatalog });
    const evidence = [...new Set(verifiedEvidenceDigests)].sort();
    let score = 0;
    if (publisherMatchesSource)
        score += 40;
    if (entryUrlWithinPublisher)
        score += 15;
    if (identityMatchesPublisher === true)
        score += 20;
    if (state === 'verified')
        score += 25;
    else if (manifest)
        score += 5;
    const trustEvidenceSha256 = manifest ? sha256(canonicalJson({ state, identity, evidence, trustSchema: manifest.trustSchema ?? null })) : undefined;
    const assessment = {
        identifier: entry.identifier,
        sourceCatalog,
        ...(publisher ? { publisher } : {}),
        publisherMatchesSource,
        ...(entryUrlHost ? { entryUrlHost } : {}),
        entryUrlWithinPublisher,
        ...(identity ? { identity } : {}),
        ...(identityMatchesPublisher !== undefined ? { identityMatchesPublisher } : {}),
        signaturePresent: manifest?.signature !== undefined,
        attestations: attestationNames(manifest),
        state,
        verifiedEvidenceDigests: evidence,
        ...(trustEvidenceSha256 ? { trustEvidenceSha256 } : {}),
        score
    };
    return { assessment, findings };
}
