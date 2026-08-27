import { createHash } from 'node:crypto';
const MAX_CANONICAL_DEPTH = 128;
const MAX_CANONICAL_NODES = 250_000;
function normalize(value, seen, depth, nodes) {
    if (++nodes.n > MAX_CANONICAL_NODES)
        throw new Error(`canonical JSON exceeds ${MAX_CANONICAL_NODES} nodes`);
    if (depth > MAX_CANONICAL_DEPTH)
        throw new Error(`canonical JSON exceeds depth ${MAX_CANONICAL_DEPTH}`);
    if (value === null || typeof value === 'string' || typeof value === 'boolean')
        return value;
    if (typeof value === 'number') {
        if (!Number.isFinite(value))
            throw new Error('canonical JSON rejects non-finite numbers');
        return Object.is(value, -0) ? 0 : value;
    }
    if (typeof value === 'undefined' || typeof value === 'bigint' || typeof value === 'function' || typeof value === 'symbol') {
        throw new Error(`canonical JSON rejects ${typeof value}`);
    }
    if (Array.isArray(value)) {
        if (seen.has(value))
            throw new Error('canonical JSON rejects cyclic structures');
        seen.add(value);
        try {
            return value.map(v => normalize(v, seen, depth + 1, nodes));
        }
        finally {
            seen.delete(value);
        }
    }
    if (value && typeof value === 'object') {
        const obj = value;
        if (seen.has(obj))
            throw new Error('canonical JSON rejects cyclic structures');
        seen.add(obj);
        try {
            return Object.fromEntries(Object.keys(obj).sort().map(k => [k, normalize(obj[k], seen, depth + 1, nodes)]));
        }
        finally {
            seen.delete(obj);
        }
    }
    throw new Error('canonical JSON encountered unsupported value');
}
export function canonicalJson(value) {
    return JSON.stringify(normalize(value, new Set(), 0, { n: 0 }));
}
export function prettyCanonicalJson(value) {
    return JSON.stringify(normalize(value, new Set(), 0, { n: 0 }), null, 2) + '\n';
}
export function sha256(value) {
    return createHash('sha256').update(value).digest('hex');
}
