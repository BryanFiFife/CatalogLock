import dns from 'node:dns/promises';
import http from 'node:http';
import https from 'node:https';
import net from 'node:net';
export const systemResolve = async (hostname) => {
    if (net.isIP(hostname))
        return [hostname];
    const rows = await dns.lookup(hostname, { all: true, verbatim: true });
    return [...new Set(rows.map((r) => r.address))];
};
function ipv4ToInt(ip) {
    return ip.split('.').reduce((n, p) => ((n << 8) | Number(p)) >>> 0, 0) >>> 0;
}
function inV4(ip, base, bits) {
    const n = ipv4ToInt(ip);
    const b = ipv4ToInt(base);
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (n & mask) === (b & mask);
}
function parseIpv6(ip) {
    const zone = ip.indexOf('%');
    if (zone >= 0)
        ip = ip.slice(0, zone);
    const mapped = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i);
    if (mapped?.[1])
        return (0xffffn << 32n) | BigInt(ipv4ToInt(mapped[1]));
    const halves = ip.split('::');
    if (halves.length > 2)
        throw new Error('invalid IPv6');
    const left = halves[0] ? halves[0].split(':').filter(Boolean) : [];
    const right = halves[1] ? halves[1].split(':').filter(Boolean) : [];
    const expandEmbedded = (parts) => {
        const out = [];
        for (const part of parts) {
            if (part.includes('.')) {
                const n = ipv4ToInt(part);
                out.push(((n >>> 16) & 0xffff).toString(16), (n & 0xffff).toString(16));
            }
            else
                out.push(part);
        }
        return out;
    };
    const l = expandEmbedded(left);
    const r = expandEmbedded(right);
    const missing = 8 - l.length - r.length;
    if (missing < 0 || (halves.length === 1 && missing !== 0))
        throw new Error('invalid IPv6');
    const full = [...l, ...Array(missing).fill('0'), ...r];
    if (full.length !== 8)
        throw new Error('invalid IPv6');
    return full.reduce((acc, part) => (acc << 16n) | BigInt(parseInt(part || '0', 16)), 0n);
}
function inV6(ip, base, bits) {
    const n = parseIpv6(ip);
    const b = parseIpv6(base);
    const shift = BigInt(128 - bits);
    return (n >> shift) === (b >> shift);
}
export function isPublicIp(ip) {
    const version = net.isIP(ip);
    if (version === 4) {
        const blocked = [
            ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
            ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
            ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
            ['224.0.0.0', 4], ['240.0.0.0', 4]
        ];
        return !blocked.some(([base, bits]) => inV4(ip, base, bits));
    }
    if (version === 6) {
        const lower = ip.toLowerCase();
        const mapped = lower.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
        if (mapped?.[1])
            return isPublicIp(mapped[1]);
        const blocked = [
            ['::', 128], ['::1', 128], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8],
            ['2001:db8::', 32], ['2001:10::', 28]
        ];
        return !blocked.some(([base, bits]) => inV6(ip, base, bits));
    }
    return false;
}
export function validateOutboundUrl(raw, policy) {
    const url = new URL(raw);
    if (url.username || url.password)
        throw new Error('URL credentials are forbidden');
    const allowedProtocols = policy.allowHttp ? ['https:', 'http:'] : ['https:'];
    if (!allowedProtocols.includes(url.protocol))
        throw new Error(`protocol ${url.protocol} is not allowed`);
    const port = Number(url.port || (url.protocol === 'https:' ? 443 : 80));
    if (!policy.allowedPorts.includes(port))
        throw new Error(`port ${port} is not allowed`);
    if (!url.hostname)
        throw new Error('URL hostname is required');
    return url;
}
async function requestPinned(url, address, policy, options) {
    const transport = url.protocol === 'https:' ? https : http;
    return await new Promise((resolve, reject) => {
        const req = transport.request({
            protocol: url.protocol,
            hostname: url.hostname,
            port: url.port || undefined,
            path: `${url.pathname}${url.search}`,
            method: options.method,
            headers: {
                accept: 'application/json, application/ai-catalog+json;q=0.9, application/mcp-server-card+json;q=0.9, text/event-stream;q=0.8, */*;q=0.1',
                'user-agent': 'CatalogLock/0.2 (+https://github.com/BryanFiFife/CatalogLock)',
                ...(options.body ? { 'content-length': String(Buffer.byteLength(options.body)) } : {}),
                ...(options.headers ?? {})
            },
            servername: url.protocol === 'https:' ? url.hostname : undefined,
            lookup: (_hostname, opts, callback) => {
                const family = net.isIP(address);
                const all = !!(opts && typeof opts === 'object' && 'all' in opts && opts.all);
                if (all)
                    callback(null, [{ address, family }]);
                else
                    callback(null, address, family);
            },
            timeout: policy.timeoutMs
        }, (res) => {
            const chunks = [];
            let bytes = 0;
            res.on('data', (chunk) => {
                bytes += chunk.length;
                if (bytes > policy.maxResponseBytes) {
                    req.destroy(new Error(`response exceeds ${policy.maxResponseBytes} bytes`));
                    return;
                }
                chunks.push(chunk);
            });
            res.on('end', () => resolve({
                url: url.toString(),
                status: res.statusCode ?? 0,
                body: Buffer.concat(chunks).toString('utf8'),
                ...(typeof res.headers['content-type'] === 'string' ? { contentType: res.headers['content-type'] } : {}),
                ...(typeof res.headers.location === 'string' ? { location: res.headers.location } : {})
            }));
        });
        req.on('timeout', () => req.destroy(new Error(`request timed out after ${policy.timeoutMs}ms`)));
        req.on('error', reject);
        if (options.body)
            req.write(options.body);
        req.end();
    });
}
async function safeRequest(rawUrl, policy, resolver, options, redirects = 0) {
    const url = validateOutboundUrl(rawUrl, policy);
    const addresses = await resolver(url.hostname);
    if (addresses.length === 0)
        throw new Error(`no addresses resolved for ${url.hostname}`);
    const bad = addresses.filter((ip) => !isPublicIp(ip));
    if (bad.length)
        throw new Error(`refusing non-public address for ${url.hostname}: ${bad.join(', ')}`);
    const result = await requestPinned(url, addresses[0], policy, options);
    if ([301, 302, 303, 307, 308].includes(result.status)) {
        if (redirects >= policy.maxRedirects)
            throw new Error('redirect limit exceeded');
        if (!result.location)
            throw new Error('redirect received without Location header');
        const next = new URL(result.location, url).toString();
        if (options.method === 'POST' && ![307, 308].includes(result.status)) {
            throw new Error(`refusing unsafe POST redirect with HTTP ${result.status}`);
        }
        return safeRequest(next, policy, resolver, options, redirects + 1);
    }
    return result;
}
export async function safeFetch(rawUrl, policy, resolver = systemResolve, redirects = 0) {
    return safeRequest(rawUrl, policy, resolver, { method: 'GET' }, redirects);
}
export async function safePostJson(rawUrl, body, policy, resolver = systemResolve, headers = {}) {
    const payload = JSON.stringify(body);
    return safeRequest(rawUrl, policy, resolver, {
        method: 'POST',
        body: payload,
        headers: { 'content-type': 'application/json', ...headers }
    });
}
export function targetToCandidateUrls(target, policy) {
    let base;
    if (/^https?:\/\//i.test(target)) {
        base = validateOutboundUrl(target, policy);
        if (base.pathname !== '/' && base.pathname !== '')
            return [base.toString()];
    }
    else {
        base = validateOutboundUrl(`https://${target}`, policy);
    }
    const canonical = new URL('/.well-known/ai-catalog.json', base).toString();
    const candidates = [canonical];
    if (policy.allowCompatibilityArdJson)
        candidates.push(new URL('/.well-known/ard.json', base).toString());
    return candidates;
}
