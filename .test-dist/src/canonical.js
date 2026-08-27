import { createHash } from 'node:crypto';
function normalize(value) {
    if (Array.isArray(value))
        return value.map(normalize);
    if (value && typeof value === 'object') {
        const obj = value;
        return Object.fromEntries(Object.keys(obj).sort().map((k) => [k, normalize(obj[k])]));
    }
    return value;
}
export function canonicalJson(value) {
    return JSON.stringify(normalize(value));
}
export function prettyCanonicalJson(value) {
    return JSON.stringify(normalize(value), null, 2) + '\n';
}
export function sha256(value) {
    return createHash('sha256').update(value).digest('hex');
}
