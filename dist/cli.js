import fs from 'node:fs/promises';
import path from 'node:path';
import { auditCatalog } from './audit.js';
import { createLockfile, serializeLockfile, VERSION } from './lockfile.js';
import { diffLockfiles } from './diff.js';
import { htmlReport } from './reporters/html.js';
import { sarifReport } from './reporters/sarif.js';
import { jsonReport } from './reporters/json.js';
import { mergePolicy, severityRank } from './policy.js';
function parseArgs(argv) {
    const out = { _: [] };
    for (let i = 0; i < argv.length; i++) {
        const a = argv[i];
        if (!a.startsWith('--')) {
            out._.push(a);
            continue;
        }
        const [rawKey, inline] = a.slice(2).split('=', 2);
        const key = rawKey;
        if (inline !== undefined) {
            out[key] = inline;
            continue;
        }
        const next = argv[i + 1];
        if (next && !next.startsWith('--')) {
            out[key] = next;
            i++;
        }
        else
            out[key] = true;
    }
    return out;
}
function help() {
    return `CatalogLock ${VERSION}

Usage:
  cataloglock scan <domain|url> [--format json|html|sarif] [--output FILE] [--policy FILE] [--fail-on LEVEL]
  cataloglock lock <domain|url> [--output cataloglock.lock.json] [--policy FILE]
  cataloglock diff <old.lock.json> <new.lock.json> [--format text|json]
  cataloglock verify <domain|url> --lock cataloglock.lock.json [--policy FILE]
  cataloglock version

MCP 2026-07-28 server/discover and primitive-surface inspection are enabled by default.
Use --no-mcp-primitives to skip tools/prompts/resources/templates; --no-mcp-discover to skip server/discover.
--no-mcp-tools remains as a deprecated compatibility alias for --no-mcp-primitives.
Authenticated/contextual profiles and read-only prompt/resource/extension probes are configured in policy JSON.
Levels: info, warning, error, critical
`;
}
async function readPolicy(file) {
    if (!file)
        return mergePolicy();
    return mergePolicy(JSON.parse(await fs.readFile(file, 'utf8')));
}
function setFailOn(policy, value) {
    if (typeof value !== 'string')
        return policy;
    if (!['info', 'warning', 'error', 'critical'].includes(value))
        throw new Error(`invalid --fail-on ${value}`);
    return mergePolicy({ ...policy, failOn: value });
}
function applyCliPolicy(policy, args) {
    const disablePrimitives = args['no-mcp-primitives'] === true || args['no-mcp-tools'] === true;
    let profiles = policy.mcpProfiles;
    if (typeof args['mcp-profile'] === 'string') {
        const wanted = new Set(args['mcp-profile'].split(',').map(x => x.trim()).filter(Boolean));
        profiles = policy.mcpProfiles.filter(p => wanted.has(p.name));
        const missing = [...wanted].filter(name => !profiles.some(p => p.name === name));
        if (missing.length)
            throw new Error(`unknown --mcp-profile: ${missing.join(', ')}`);
        if (!profiles.length)
            throw new Error('--mcp-profile selected no profiles');
    }
    return mergePolicy({
        ...policy,
        mcpProfiles: profiles,
        ...(disablePrimitives ? { inspectMcpPrimitives: false } : {}),
        ...(args['no-mcp-discover'] === true ? { inspectMcpDiscover: false } : {}),
        ...(args['require-mcp-inspection'] === true ? { requireMcpInspection: true } : {}),
        ...(args['require-verified-trust'] === true ? { requireVerifiedTrust: true } : {})
    });
}
function shouldFail(findings, threshold) {
    return findings.some(f => severityRank(f.severity) >= severityRank(threshold));
}
async function writeOrStdout(content, file) {
    if (typeof file === 'string') {
        await fs.mkdir(path.dirname(path.resolve(file)), { recursive: true });
        await fs.writeFile(file, content);
    }
    else
        process.stdout.write(content);
}
export async function main(argv = process.argv.slice(2)) {
    const args = parseArgs(argv);
    const command = args._[0];
    if (args.version === true || command === '--version' || command === 'version') {
        process.stdout.write(`${VERSION}\n`);
        return 0;
    }
    if (!command || command === 'help' || args.help === true) {
        process.stdout.write(help());
        return 0;
    }
    if (command === 'scan' || command === 'lock' || command === 'verify') {
        const target = args._[1];
        if (!target)
            throw new Error(`${command} requires a target`);
        let policy = await readPolicy(typeof args.policy === 'string' ? args.policy : undefined);
        policy = setFailOn(policy, args['fail-on']);
        policy = applyCliPolicy(policy, args);
        const { result } = await auditCatalog(target, { policy });
        if (command === 'scan') {
            const format = typeof args.format === 'string' ? args.format : 'json';
            if (!['json', 'html', 'sarif'].includes(format))
                throw new Error(`unsupported scan format: ${format}`);
            const content = format === 'html' ? htmlReport(result) : format === 'sarif' ? sarifReport(result.findings) : jsonReport(result);
            await writeOrStdout(content, args.output);
            return shouldFail(result.findings, policy.failOn) ? 2 : 0;
        }
        const lock = createLockfile(result, policy);
        if (command === 'lock') {
            await writeOrStdout(serializeLockfile(lock), typeof args.output === 'string' ? args.output : 'cataloglock.lock.json');
            return shouldFail(result.findings, policy.failOn) ? 2 : 0;
        }
        const lockPath = typeof args.lock === 'string' ? args.lock : 'cataloglock.lock.json';
        const old = JSON.parse(await fs.readFile(lockPath, 'utf8'));
        const diff = diffLockfiles(old, lock);
        await writeOrStdout(jsonReport(diff), args.output);
        return diff.changed || shouldFail(result.findings, policy.failOn) ? 3 : 0;
    }
    if (command === 'diff') {
        const a = args._[1], b = args._[2];
        if (!a || !b)
            throw new Error('diff requires two lockfiles');
        const old = JSON.parse(await fs.readFile(a, 'utf8'));
        const cur = JSON.parse(await fs.readFile(b, 'utf8'));
        const diff = diffLockfiles(old, cur);
        if (args.format !== undefined && args.format !== 'json' && args.format !== 'text')
            throw new Error(`unsupported diff format: ${String(args.format)}`);
        if (args.format === 'json')
            await writeOrStdout(jsonReport(diff), args.output);
        else {
            const lines = [
                `CatalogLock diff: ${diff.changed ? 'CHANGED' : 'clean'}`,
                `Blast radius: ${JSON.stringify(diff.blastRadius)}`,
                ...diff.changes.map(c => `[${c.severity.toUpperCase()}] ${c.kind}: ${c.message}`)
            ];
            await writeOrStdout(lines.join('\n') + '\n', args.output);
        }
        return diff.changed ? 3 : 0;
    }
    throw new Error(`unknown command: ${command}`);
}
main().then(code => { process.exitCode = code; }).catch(err => { console.error(err instanceof Error ? err.message : String(err)); process.exitCode = 1; });
