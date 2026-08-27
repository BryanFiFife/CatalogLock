import { safeFetch, safePostJson } from './net.js';
import { canonicalJson, sha256 } from './canonical.js';
class MethodNotFound extends Error {
}
function isObject(v) { return !!v && typeof v === 'object' && !Array.isArray(v); }
function failureSeverity(policy) { return policy.requireMcpInspection ? 'error' : 'warning'; }
function parseJsonRpcMessages(body) {
    const trimmed = body.trim();
    if (!trimmed)
        throw new Error('empty MCP response');
    if (trimmed.startsWith('{')) {
        const parsed = JSON.parse(trimmed);
        if (!isObject(parsed))
            throw new Error('MCP response must be a JSON object');
        return [parsed];
    }
    const out = [];
    const events = trimmed.split(/\r?\n\r?\n/);
    for (const event of events) {
        const data = event.split(/\r?\n/).filter(line => line.startsWith('data:')).map(line => line.slice(5).trim()).join('\n');
        if (!data)
            continue;
        try {
            const parsed = JSON.parse(data);
            if (isObject(parsed))
                out.push(parsed);
        }
        catch { /* other SSE events can be notifications */ }
    }
    if (!out.length)
        throw new Error('MCP response is neither JSON nor parseable SSE JSON');
    return out;
}
function encodeHeaderValue(value) {
    const sentinel = /^=\?base64\?.*\?=$/s.test(value);
    const safe = !sentinel && value.length > 0 && value.trim() === value && /^[\x20-\x7e\t]+$/.test(value) && !/[\r\n]/.test(value);
    return safe ? value : `=?base64?${Buffer.from(value, 'utf8').toString('base64')}?=`;
}
function requestParams(policy, profile, rest = {}) {
    return {
        ...rest,
        _meta: {
            'io.modelcontextprotocol/protocolVersion': policy.mcpProtocolVersion,
            'io.modelcontextprotocol/clientInfo': { name: 'cataloglock', version: '0.3.0' },
            'io.modelcontextprotocol/clientCapabilities': profile.clientCapabilities
        }
    };
}
function cacheFromResult(result, method) {
    const ttlMs = result.ttlMs;
    const cacheScope = result.cacheScope;
    if (typeof ttlMs !== 'number' || !Number.isFinite(ttlMs) || ttlMs < 0)
        throw new Error(`${method} result requires non-negative ttlMs`);
    if (cacheScope !== 'public' && cacheScope !== 'private')
        throw new Error(`${method} result requires cacheScope public|private`);
    return { ttlMs, cacheScope };
}
async function rpc(endpoint, method, params, policy, requester, headers, id, cacheable, name) {
    const reqHeaders = {
        ...headers,
        'MCP-Protocol-Version': policy.mcpProtocolVersion,
        'Mcp-Method': method,
        ...(name !== undefined ? { 'Mcp-Name': encodeHeaderValue(name) } : {})
    };
    const response = await requester(endpoint, { jsonrpc: '2.0', id, method, params }, policy, reqHeaders);
    if (response.status === 404)
        throw new MethodNotFound(`${method}: HTTP 404 Method not found`);
    if (response.contentType && !/(?:application\/(?:json|[^;]+\+json)|text\/event-stream)/i.test(response.contentType))
        throw new Error(`${method} returned unsupported Content-Type ${response.contentType}`);
    const messages = parseJsonRpcMessages(response.body);
    const msg = messages.find(m => m.id === id);
    if (!msg) {
        const unboundError = messages.find(m => (m.id === null || m.id === undefined) && isObject(m.error));
        if (unboundError) {
            if (unboundError.jsonrpc !== '2.0')
                throw new Error(`${method} response jsonrpc must equal 2.0`);
            const error = unboundError.error;
            const code = typeof error.code === 'number' ? error.code : undefined;
            const message = typeof error.message === 'string' ? error.message : 'MCP error';
            if (code === -32601 || response.status === 404)
                throw new MethodNotFound(`${method}: ${message}`);
            throw new Error(`${method} JSON-RPC error${code !== undefined ? ` ${code}` : ''}: ${message}`);
        }
        throw new Error(`${method} response does not contain the matching request id`);
    }
    if (msg.jsonrpc !== '2.0')
        throw new Error(`${method} response jsonrpc must equal 2.0`);
    if (msg.id !== id)
        throw new Error(`${method} response id does not match request id`);
    if (isObject(msg.error)) {
        const code = typeof msg.error.code === 'number' ? msg.error.code : undefined;
        const message = typeof msg.error.message === 'string' ? msg.error.message : 'MCP error';
        if (code === -32601 || response.status === 404)
            throw new MethodNotFound(`${method}: ${message}`);
        throw new Error(`${method} JSON-RPC error${code !== undefined ? ` ${code}` : ''}: ${message}`);
    }
    if (response.status < 200 || response.status >= 300)
        throw new Error(`${method} returned HTTP ${response.status}`);
    if (!isObject(msg.result))
        throw new Error(`${method} response is missing result object`);
    if (msg.result.resultType !== 'complete') {
        if (msg.result.resultType === 'input_required')
            throw new Error(`${method} returned input_required; CatalogLock does not satisfy interactive MRTR during inspection`);
        throw new Error(`${method} result requires resultType="complete" for MCP ${policy.mcpProtocolVersion}`);
    }
    return { result: msg.result, ...(cacheable ? { cache: cacheFromResult(msg.result, method) } : {}) };
}
function cardRemotes(card) {
    if (!isObject(card) || !Array.isArray(card.remotes))
        return [];
    const out = [];
    card.remotes.forEach((raw, index) => {
        if (!isObject(raw) || typeof raw.url !== 'string')
            return;
        const transport = typeof raw.type === 'string' ? raw.type : typeof raw.transportType === 'string' ? raw.transportType : '';
        if (transport !== 'streamable-http')
            return;
        const requiredHeaders = [];
        if (Array.isArray(raw.headers)) {
            for (const h of raw.headers)
                if (isObject(h) && h.isRequired === true && typeof h.name === 'string')
                    requiredHeaders.push(h.name);
        }
        if (isObject(raw.auth) && !requiredHeaders.some(h => /^authorization$/i.test(h)))
            requiredHeaders.push('Authorization');
        const explicitId = typeof raw.id === 'string' ? raw.id : typeof raw.name === 'string' ? raw.name : undefined;
        out.push({ id: explicitId ? `declared:${explicitId}` : `remote-${index}`, index, endpoint: raw.url, requiredHeaders: [...new Set(requiredHeaders)].sort((a, b) => a.localeCompare(b)) });
    });
    return out;
}
function isConcreteEndpoint(url) { return !/[{}]/.test(url); }
function isMcpCardEntry(entry) { return entry.type === 'application/mcp-server-card+json' || entry.type === 'application/mcp-server+json'; }
function profileHeaders(profile, env) {
    const headers = {};
    const missing = [];
    for (const [header, envName] of Object.entries(profile.headersFromEnv ?? {})) {
        const value = env[envName];
        if (value === undefined || value === '')
            missing.push(envName);
        else
            headers[header] = value;
    }
    return { ...(missing.length ? {} : { headers }), missing };
}
function profileFingerprint(profile) {
    return sha256(canonicalJson({ name: profile.name, clientCapabilities: profile.clientCapabilities, headersFromEnv: profile.headersFromEnv ?? {} }));
}
function headerNames(profile) { return Object.keys(profile.headersFromEnv ?? {}).map(x => x.toLowerCase()); }
function validateSchemaComplexity(schema, label) {
    let nodes = 0;
    let refs = 0;
    const walk = (v, depth) => {
        if (++nodes > 10000)
            throw new Error(`${label} JSON Schema exceeds 10000 nodes`);
        if (depth > 64)
            throw new Error(`${label} JSON Schema exceeds depth 64`);
        if (!v || typeof v !== 'object')
            return;
        if (Array.isArray(v)) {
            for (const x of v)
                walk(x, depth + 1);
            return;
        }
        for (const [k, x] of Object.entries(v)) {
            if (k === '$ref' && ++refs > 1000)
                throw new Error(`${label} JSON Schema exceeds 1000 $ref values`);
            walk(x, depth + 1);
        }
    };
    walk(schema, 0);
}
function toolHeaderErrors(tool) {
    const schema = tool.inputSchema;
    if (!isObject(schema))
        return [];
    const errors = [];
    const names = new Set();
    const token = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
    const visit = (node, staticReachable, path) => {
        if (!isObject(node))
            return;
        if (Object.prototype.hasOwnProperty.call(node, 'x-mcp-header')) {
            const h = node['x-mcp-header'];
            if (!staticReachable)
                errors.push(`${path}: x-mcp-header is not statically reachable through properties only`);
            if (typeof h !== 'string' || !h || !token.test(h))
                errors.push(`${path}: x-mcp-header is not a valid HTTP token`);
            else {
                const lower = h.toLowerCase();
                if (names.has(lower))
                    errors.push(`${path}: duplicate x-mcp-header ${h}`);
                names.add(lower);
            }
            if (!['string', 'integer', 'boolean'].includes(String(node.type)))
                errors.push(`${path}: x-mcp-header may only annotate string, integer or boolean properties`);
        }
        for (const [k, v] of Object.entries(node)) {
            if (k === 'properties' && isObject(v))
                for (const [pk, pv] of Object.entries(v))
                    visit(pv, staticReachable, `${path}.properties.${pk}`);
            else if (k !== 'x-mcp-header' && k !== 'properties' && v && typeof v === 'object')
                visit(v, false, `${path}.${k}`);
        }
    };
    visit(schema, true, 'inputSchema');
    return errors;
}
function normalizeItem(raw, keyField, method) {
    if (!isObject(raw) || typeof raw[keyField] !== 'string' || !raw[keyField])
        throw new Error(`${method} returned item without valid ${keyField}`);
    const key = raw[keyField];
    if (method === 'tools/list') {
        if (!Object.prototype.hasOwnProperty.call(raw, 'inputSchema'))
            throw new Error(`tools/list tool ${key} is missing inputSchema`);
        validateSchemaComplexity(raw.inputSchema, `tool ${key} inputSchema`);
        if (Object.prototype.hasOwnProperty.call(raw, 'outputSchema'))
            validateSchemaComplexity(raw.outputSchema, `tool ${key} outputSchema`);
        const headerErrors = toolHeaderErrors(raw);
        if (headerErrors.length)
            return { rejectedToolName: key, rejectedToolReason: headerErrors.join('; ') };
    }
    return { item: { key, sha256: sha256(canonicalJson(raw)) } };
}
async function listCollection(endpoint, method, field, keyField, policy, profile, requester, headers, startId, onRejectedTool) {
    const items = new Map();
    const caches = [];
    let cursor;
    const seenCursors = new Set();
    let id = startId;
    for (let page = 0; page < policy.maxMcpPages; page++) {
        const params = requestParams(policy, profile, cursor ? { cursor } : {});
        const rr = await rpc(endpoint, method, params, policy, requester, headers, id++, true);
        if (!Array.isArray(rr.result[field]))
            throw new Error(`${method} response is missing result.${field}`);
        caches.push(rr.cache);
        for (const raw of rr.result[field]) {
            const normalized = normalizeItem(raw, keyField, method);
            if (!normalized.item) {
                if (normalized.rejectedToolName && normalized.rejectedToolReason)
                    onRejectedTool?.(normalized.rejectedToolName, normalized.rejectedToolReason);
                continue;
            }
            const item = normalized.item;
            if (items.has(item.key))
                throw new Error(`${method} returned duplicate ${keyField} ${item.key}`);
            items.set(item.key, item);
            if (items.size > policy.maxMcpItems)
                throw new Error(`${method} exceeds maxMcpItems=${policy.maxMcpItems}`);
        }
        const next = typeof rr.result.nextCursor === 'string' && rr.result.nextCursor ? rr.result.nextCursor : undefined;
        if (!next) {
            const sorted = [...items.values()].sort((a, b) => a.key.localeCompare(b.key));
            return { collection: { items: sorted, itemsSha256: sha256(canonicalJson(sorted)), pages: page + 1, cacheSha256: sha256(canonicalJson(caches)), caches }, nextId: id };
        }
        if (seenCursors.has(next))
            throw new Error(`${method} repeated pagination cursor ${next}`);
        seenCursors.add(next);
        cursor = next;
    }
    throw new Error(`${method} exceeded maxMcpPages=${policy.maxMcpPages}`);
}
function probeMatches(probe, identifier, profile, remoteId) {
    return (!probe.identifier || probe.identifier === identifier) && (!probe.profile || probe.profile === profile) && (!probe.remoteId || probe.remoteId === remoteId);
}
async function runPromptProbe(p, endpoint, policy, profile, requester, headers, id) {
    const params = requestParams(policy, profile, { name: p.name, ...(p.arguments ? { arguments: p.arguments } : {}) });
    const rr = await rpc(endpoint, 'prompts/get', params, policy, requester, headers, id, false, p.name);
    if (!Array.isArray(rr.result.messages))
        throw new Error('prompts/get response is missing messages');
    const key = `prompt:${p.name}:${sha256(canonicalJson(p.arguments ?? {}))}`;
    return { snapshot: { method: 'prompts/get', key, sha256: sha256(canonicalJson(rr.result)) }, nextId: id + 1 };
}
async function runResourceProbe(p, endpoint, policy, profile, requester, headers, id) {
    const rr = await rpc(endpoint, 'resources/read', requestParams(policy, profile, { uri: p.uri }), policy, requester, headers, id, true, p.uri);
    if (!Array.isArray(rr.result.contents))
        throw new Error('resources/read response is missing contents');
    return { snapshot: { method: 'resources/read', key: `resource:${p.uri}`, sha256: sha256(canonicalJson(rr.result)), ...(rr.cache ? { cache: rr.cache } : {}) }, nextId: id + 1 };
}
async function runExtensionProbe(p, endpoint, policy, profile, requester, headers, id) {
    if (p.method === 'tools/call')
        throw new Error('tools/call is forbidden as a CatalogLock probe');
    const params = requestParams(policy, profile, p.params ?? {});
    const name = p.name ?? p.uri;
    const rr = await rpc(endpoint, p.method, params, policy, requester, headers, id, p.cacheable === true, name);
    return { snapshot: { method: p.method, key: `extension:${p.method}:${sha256(canonicalJson(p.params ?? {}))}`, sha256: sha256(canonicalJson(rr.result)), ...(rr.cache ? { cache: rr.cache } : {}) }, nextId: id + 1 };
}
async function inspectSurface(identifier, remote, cardSha256, cardUrl, policy, profile, requester, headers, findings) {
    let id = 1;
    let discover;
    let rawCapabilities;
    if (policy.inspectMcpDiscover) {
        try {
            const rr = await rpc(remote.endpoint, 'server/discover', requestParams(policy, profile), policy, requester, headers, id++, true);
            if (!Array.isArray(rr.result.supportedVersions) || rr.result.supportedVersions.some(x => typeof x !== 'string'))
                throw new Error('server/discover supportedVersions must be an array of strings');
            if (!isObject(rr.result.capabilities))
                throw new Error('server/discover capabilities must be an object');
            rawCapabilities = rr.result.capabilities;
            if (!rr.result.supportedVersions.includes(policy.mcpProtocolVersion))
                findings.push({ ruleId: 'mcp/discover-version-inconsistent', severity: 'error', message: `server/discover does not advertise the protocol version that just succeeded: ${policy.mcpProtocolVersion}`, location: remote.endpoint, evidence: { identifier, profile: profile.name, remoteId: remote.id } });
            const meta = isObject(rr.result._meta) ? rr.result._meta : undefined;
            const serverInfo = meta?.['io.modelcontextprotocol/serverInfo'];
            const extensions = isObject(rawCapabilities.extensions) ? rawCapabilities.extensions : undefined;
            discover = {
                sha256: sha256(canonicalJson(rr.result)),
                supportedVersions: [...rr.result.supportedVersions].sort(),
                capabilitiesSha256: sha256(canonicalJson(rawCapabilities)),
                ...(extensions ? { extensionsSha256: sha256(canonicalJson(extensions)) } : {}),
                ...(typeof rr.result.instructions === 'string' ? { instructionsSha256: sha256(rr.result.instructions) } : {}),
                ...(serverInfo !== undefined ? { serverInfoSha256: sha256(canonicalJson(serverInfo)) } : {}),
                cache: rr.cache
            };
        }
        catch (e) {
            findings.push({ ruleId: 'mcp/server-discover', severity: failureSeverity(policy), message: e instanceof Error ? e.message : String(e), location: remote.endpoint, evidence: { identifier, profile: profile.name, remoteId: remote.id } });
            if (policy.requireMcpInspection)
                return undefined;
        }
    }
    let tools, prompts, resources, resourceTemplates;
    if (policy.inspectMcpPrimitives) {
        const specs = [
            ['tools/list', 'tools', 'name', 'tools', 'tools'],
            ['prompts/list', 'prompts', 'name', 'prompts', 'prompts'],
            ['resources/list', 'resources', 'uri', 'resources', 'resources'],
            ['resources/templates/list', 'resourceTemplates', 'uriTemplate', 'resourceTemplates', 'resources']
        ];
        for (const [method, field, key, dest, cap] of specs) {
            if (rawCapabilities && !Object.prototype.hasOwnProperty.call(rawCapabilities, cap))
                continue;
            try {
                const out = await listCollection(remote.endpoint, method, field, key, policy, profile, requester, headers, id, (name, reason) => findings.push({ ruleId: 'mcp/tool-header-annotation', severity: 'warning', message: `Excluded tool ${name}: ${reason}`, location: remote.endpoint, evidence: { identifier, profile: profile.name, remoteId: remote.id, tool: name } }));
                id = out.nextId;
                if (dest === 'tools')
                    tools = out.collection;
                else if (dest === 'prompts')
                    prompts = out.collection;
                else if (dest === 'resources')
                    resources = out.collection;
                else
                    resourceTemplates = out.collection;
            }
            catch (e) {
                if (e instanceof MethodNotFound) {
                    if (rawCapabilities && Object.prototype.hasOwnProperty.call(rawCapabilities, cap))
                        findings.push({ ruleId: 'mcp/capability-method-mismatch', severity: 'error', message: `server/discover advertises ${cap} but ${method} is unavailable`, location: remote.endpoint, evidence: { identifier, profile: profile.name, remoteId: remote.id } });
                    continue;
                }
                findings.push({ ruleId: `mcp/${method.replace('/', '-')}`, severity: failureSeverity(policy), message: e instanceof Error ? e.message : String(e), location: remote.endpoint, evidence: { identifier, profile: profile.name, remoteId: remote.id } });
                if (policy.requireMcpInspection)
                    return undefined;
            }
        }
    }
    const probes = [];
    for (const p of policy.mcpPromptProbes.filter(p => probeMatches(p, identifier, profile.name, remote.id))) {
        try {
            const o = await runPromptProbe(p, remote.endpoint, policy, profile, requester, headers, id);
            id = o.nextId;
            probes.push(o.snapshot);
        }
        catch (e) {
            findings.push({ ruleId: 'mcp/prompt-probe', severity: failureSeverity(policy), message: e instanceof Error ? e.message : String(e), location: remote.endpoint, evidence: { identifier, profile: profile.name, remoteId: remote.id, name: p.name } });
            if (policy.requireMcpInspection)
                return undefined;
        }
    }
    for (const p of policy.mcpResourceProbes.filter(p => probeMatches(p, identifier, profile.name, remote.id))) {
        try {
            const o = await runResourceProbe(p, remote.endpoint, policy, profile, requester, headers, id);
            id = o.nextId;
            probes.push(o.snapshot);
        }
        catch (e) {
            findings.push({ ruleId: 'mcp/resource-probe', severity: failureSeverity(policy), message: e instanceof Error ? e.message : String(e), location: remote.endpoint, evidence: { identifier, profile: profile.name, remoteId: remote.id, uri: p.uri } });
            if (policy.requireMcpInspection)
                return undefined;
        }
    }
    for (const p of policy.mcpExtensionProbes.filter(p => probeMatches(p, identifier, profile.name, remote.id))) {
        try {
            const o = await runExtensionProbe(p, remote.endpoint, policy, profile, requester, headers, id);
            id = o.nextId;
            probes.push(o.snapshot);
        }
        catch (e) {
            findings.push({ ruleId: 'mcp/extension-probe', severity: failureSeverity(policy), message: e instanceof Error ? e.message : String(e), location: remote.endpoint, evidence: { identifier, profile: profile.name, remoteId: remote.id, method: p.method } });
            if (policy.requireMcpInspection)
                return undefined;
        }
    }
    probes.sort((a, b) => `${a.method}:${a.key}`.localeCompare(`${b.method}:${b.key}`));
    const base = {
        surfaceId: `${identifier}#${remote.id}#profile:${profile.name}`,
        identifier, remoteId: remote.id, remoteIndex: remote.index,
        ...(cardUrl ? { cardUrl } : {}), cardSha256, endpoint: new URL(remote.endpoint).toString(), protocolVersion: policy.mcpProtocolVersion,
        profile: profile.name, profileSha256: profileFingerprint(profile), ...(discover ? { discover } : {}), ...(tools ? { tools } : {}), ...(prompts ? { prompts } : {}), ...(resources ? { resources } : {}), ...(resourceTemplates ? { resourceTemplates } : {}), probes
    };
    return { ...base, surfaceSha256: sha256(canonicalJson(base)) };
}
export async function inspectMcpSurfaces(result, policy, options = {}) {
    if (!policy.inspectMcpPrimitives && !policy.inspectMcpDiscover && !policy.mcpPromptProbes.length && !policy.mcpResourceProbes.length && !policy.mcpExtensionProbes.length)
        return { surfaces: [], findings: [] };
    const fetcher = options.fetcher ?? ((url, p) => safeFetch(url, p, options.addressResolver));
    const requester = options.requester ?? ((url, body, p, headers) => safePostJson(url, body, p, options.addressResolver, headers));
    const env = options.env ?? process.env;
    const findings = [];
    const surfaces = [];
    for (const catalog of result.catalogs) {
        for (const entry of catalog.catalog.entries) {
            if (!isMcpCardEntry(entry))
                continue;
            let card;
            let cardUrl;
            try {
                if (typeof entry.url === 'string') {
                    cardUrl = entry.url;
                    const f = await fetcher(entry.url, policy);
                    if (f.status < 200 || f.status >= 300)
                        throw new Error(`MCP Server Card returned HTTP ${f.status}`);
                    card = JSON.parse(f.body);
                }
                else if (Object.prototype.hasOwnProperty.call(entry, 'data'))
                    card = entry.data;
                else
                    throw new Error('MCP entry has neither url nor inline data');
            }
            catch (e) {
                findings.push({ ruleId: 'mcp/card-fetch', severity: failureSeverity(policy), message: e instanceof Error ? e.message : String(e), location: cardUrl ?? catalog.url, evidence: { identifier: entry.identifier } });
                continue;
            }
            const cardSha256 = sha256(canonicalJson(card));
            const remotes = cardRemotes(card);
            if (!remotes.length) {
                findings.push({ ruleId: 'mcp/no-streamable-http', severity: failureSeverity(policy), message: 'MCP Server Card has no streamable-http remotes', location: cardUrl ?? catalog.url, evidence: { identifier: entry.identifier } });
                continue;
            }
            for (const remote of remotes) {
                if (!isConcreteEndpoint(remote.endpoint)) {
                    findings.push({ ruleId: 'mcp/templated-remote', severity: failureSeverity(policy), message: `MCP remote ${remote.id} is templated and cannot be inspected without concrete values`, location: cardUrl ?? catalog.url, evidence: { identifier: entry.identifier, remoteId: remote.id } });
                    continue;
                }
                for (const profile of policy.mcpProfiles) {
                    const hp = profileHeaders(profile, env);
                    if (hp.missing.length) {
                        findings.push({ ruleId: 'mcp/profile-secret-missing', severity: failureSeverity(policy), message: `MCP profile ${profile.name} is missing required environment variables: ${hp.missing.join(', ')}`, location: remote.endpoint, evidence: { identifier: entry.identifier, remoteId: remote.id, profile: profile.name, envNames: hp.missing } });
                        continue;
                    }
                    const available = headerNames(profile);
                    const missingRequired = remote.requiredHeaders.filter(h => !available.includes(h.toLowerCase()));
                    if (missingRequired.length) {
                        findings.push({ ruleId: 'mcp/auth-required', severity: failureSeverity(policy), message: `MCP remote requires headers not supplied by profile ${profile.name}: ${missingRequired.join(', ')}`, location: remote.endpoint, evidence: { identifier: entry.identifier, remoteId: remote.id, profile: profile.name } });
                        continue;
                    }
                    try {
                        const surface = await inspectSurface(entry.identifier, remote, cardSha256, cardUrl, policy, profile, requester, hp.headers ?? {}, findings);
                        if (surface)
                            surfaces.push(surface);
                    }
                    catch (e) {
                        findings.push({ ruleId: 'mcp/inspect', severity: failureSeverity(policy), message: e instanceof Error ? e.message : String(e), location: remote.endpoint, evidence: { identifier: entry.identifier, remoteId: remote.id, profile: profile.name } });
                    }
                }
            }
        }
    }
    surfaces.sort((a, b) => a.surfaceId.localeCompare(b.surfaceId));
    findings.sort((a, b) => `${a.severity}:${a.ruleId}:${a.location ?? ''}:${a.message}`.localeCompare(`${b.severity}:${b.ruleId}:${b.location ?? ''}:${b.message}`));
    return { surfaces, findings };
}
