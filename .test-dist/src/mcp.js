import { safeFetch, safePostJson } from './net.js';
import { canonicalJson, sha256 } from './canonical.js';
function isObject(v) {
    return !!v && typeof v === 'object' && !Array.isArray(v);
}
function severityForInspectionFailure(policy) {
    return policy.requireMcpInspection ? 'error' : 'warning';
}
function cardRemote(card) {
    if (!isObject(card) || !Array.isArray(card.remotes))
        return { authRequired: false };
    for (const raw of card.remotes) {
        if (!isObject(raw) || typeof raw.url !== 'string')
            continue;
        const transport = typeof raw.type === 'string' ? raw.type : typeof raw.transportType === 'string' ? raw.transportType : '';
        if (transport !== 'streamable-http')
            continue;
        let authRequired = false;
        if (Array.isArray(raw.headers)) {
            authRequired = raw.headers.some((h) => isObject(h) && h.isRequired === true);
        }
        if (isObject(raw.auth))
            authRequired = true;
        return { endpoint: raw.url, authRequired };
    }
    return { authRequired: false };
}
function parseJsonRpc(body) {
    const trimmed = body.trim();
    if (!trimmed)
        throw new Error('empty MCP response');
    if (trimmed.startsWith('{')) {
        const parsed = JSON.parse(trimmed);
        if (!isObject(parsed))
            throw new Error('MCP response must be a JSON object');
        return parsed;
    }
    const dataLines = trimmed.split(/\r?\n/).filter((line) => line.startsWith('data:')).map((line) => line.slice(5).trim()).filter(Boolean);
    for (const line of dataLines.reverse()) {
        try {
            const parsed = JSON.parse(line);
            if (isObject(parsed))
                return parsed;
        }
        catch {
            continue;
        }
    }
    throw new Error('MCP response is neither JSON nor parseable SSE JSON');
}
function normalizeTool(raw) {
    if (!isObject(raw) || typeof raw.name !== 'string' || !raw.name)
        throw new Error('tools/list returned a tool without a valid name');
    return raw;
}
function lockTool(tool) {
    return {
        name: tool.name,
        toolSha256: sha256(canonicalJson(tool)),
        ...(Object.prototype.hasOwnProperty.call(tool, 'inputSchema') ? { inputSchemaSha256: sha256(canonicalJson(tool.inputSchema)) } : {}),
        ...(Object.prototype.hasOwnProperty.call(tool, 'outputSchema') ? { outputSchemaSha256: sha256(canonicalJson(tool.outputSchema)) } : {})
    };
}
async function listTools(endpoint, policy, requester) {
    const byName = new Map();
    let cursor;
    const seenCursors = new Set();
    for (let page = 0; page < policy.maxMcpPages; page++) {
        const params = {
            _meta: {
                'io.modelcontextprotocol/clientInfo': {
                    name: 'cataloglock',
                    version: '0.2.0'
                }
            }
        };
        if (cursor)
            params.cursor = cursor;
        const response = await requester(endpoint, { jsonrpc: '2.0', id: page + 1, method: 'tools/list', params }, policy, {
            'MCP-Protocol-Version': policy.mcpProtocolVersion,
            'Mcp-Method': 'tools/list'
        });
        if (response.status < 200 || response.status >= 300)
            throw new Error(`tools/list returned HTTP ${response.status}`);
        const rpc = parseJsonRpc(response.body);
        if (isObject(rpc.error)) {
            const code = typeof rpc.error.code === 'number' ? ` ${rpc.error.code}` : '';
            const message = typeof rpc.error.message === 'string' ? `: ${rpc.error.message}` : '';
            throw new Error(`tools/list JSON-RPC error${code}${message}`);
        }
        if (!isObject(rpc.result) || !Array.isArray(rpc.result.tools))
            throw new Error('tools/list response is missing result.tools');
        for (const raw of rpc.result.tools) {
            const tool = normalizeTool(raw);
            if (byName.has(tool.name))
                throw new Error(`tools/list returned duplicate tool name ${tool.name}`);
            byName.set(tool.name, lockTool(tool));
            if (byName.size > policy.maxMcpTools)
                throw new Error(`MCP server exceeds maxMcpTools=${policy.maxMcpTools}`);
        }
        const next = typeof rpc.result.nextCursor === 'string' && rpc.result.nextCursor ? rpc.result.nextCursor : undefined;
        if (!next)
            return [...byName.values()].sort((a, b) => a.name.localeCompare(b.name));
        if (seenCursors.has(next))
            throw new Error(`tools/list repeated pagination cursor ${next}`);
        seenCursors.add(next);
        cursor = next;
    }
    throw new Error(`tools/list exceeded maxMcpPages=${policy.maxMcpPages}`);
}
function isMcpCardEntry(entry) {
    return entry.type === 'application/mcp-server-card+json' || entry.type === 'application/mcp-server+json';
}
export async function inspectMcpSurfaces(result, policy, options = {}) {
    if (!policy.inspectMcpTools)
        return { surfaces: [], findings: [] };
    const fetcher = options.fetcher ?? ((url, p) => safeFetch(url, p, options.addressResolver));
    const requester = options.requester ?? ((url, body, p, headers) => safePostJson(url, body, p, options.addressResolver, headers));
    const findings = [];
    const surfaces = [];
    for (const catalog of result.catalogs) {
        for (const entry of catalog.catalog.entries) {
            if (!isMcpCardEntry(entry))
                continue;
            const failureSeverity = severityForInspectionFailure(policy);
            let card;
            let cardSha256;
            let cardUrl;
            if (typeof entry.url === 'string') {
                cardUrl = entry.url;
                try {
                    const fetched = await fetcher(entry.url, policy);
                    if (fetched.status < 200 || fetched.status >= 300) {
                        findings.push({ ruleId: 'mcp/card-fetch', severity: failureSeverity, message: `MCP Server Card returned HTTP ${fetched.status}`, location: entry.url, evidence: { identifier: entry.identifier } });
                        continue;
                    }
                    card = JSON.parse(fetched.body);
                    cardSha256 = sha256(canonicalJson(card));
                }
                catch (err) {
                    findings.push({ ruleId: 'mcp/card-fetch', severity: failureSeverity, message: err instanceof Error ? err.message : String(err), location: entry.url, evidence: { identifier: entry.identifier } });
                    continue;
                }
            }
            else if (Object.prototype.hasOwnProperty.call(entry, 'data')) {
                card = entry.data;
                cardSha256 = sha256(canonicalJson(card));
            }
            else {
                findings.push({ ruleId: 'mcp/card-missing', severity: failureSeverity, message: 'MCP entry has neither url nor inline data', location: catalog.url, evidence: { identifier: entry.identifier } });
                continue;
            }
            const remote = cardRemote(card);
            if (!remote.endpoint) {
                findings.push({ ruleId: 'mcp/no-streamable-http', severity: failureSeverity, message: 'MCP Server Card has no streamable-http remote endpoint', location: cardUrl ?? catalog.url, evidence: { identifier: entry.identifier } });
                continue;
            }
            if (remote.authRequired) {
                findings.push({
                    ruleId: 'mcp/auth-required',
                    severity: failureSeverity,
                    message: 'MCP tool-surface inspection could not run because the Server Card declares required authentication',
                    location: remote.endpoint,
                    evidence: { identifier: entry.identifier }
                });
                continue;
            }
            try {
                const tools = await listTools(remote.endpoint, policy, requester);
                const toolsSha256 = sha256(canonicalJson(tools));
                surfaces.push({
                    identifier: entry.identifier,
                    ...(cardUrl ? { cardUrl } : {}),
                    cardSha256,
                    endpoint: new URL(remote.endpoint).toString(),
                    protocolVersion: policy.mcpProtocolVersion,
                    toolsSha256,
                    tools
                });
            }
            catch (err) {
                findings.push({
                    ruleId: 'mcp/tools-list',
                    severity: failureSeverity,
                    message: err instanceof Error ? err.message : String(err),
                    location: remote.endpoint,
                    evidence: { identifier: entry.identifier }
                });
            }
        }
    }
    surfaces.sort((a, b) => a.identifier.localeCompare(b.identifier) || a.endpoint.localeCompare(b.endpoint));
    findings.sort((a, b) => `${a.severity}:${a.ruleId}:${a.location ?? ''}:${a.message}`.localeCompare(`${b.severity}:${b.ruleId}:${b.location ?? ''}:${b.message}`));
    return { surfaces, findings };
}
