import fs from 'node:fs/promises';
import { resolveCatalogs } from './resolver.js';
import { createLockfile, serializeLockfile } from './lockfile.js';
import { mergePolicy, severityRank } from './policy.js';
import { sarifReport } from './reporters/sarif.js';
import { htmlReport } from './reporters/html.js';
function input(name, fallback = '') { return process.env[`INPUT_${name.replace(/ /g, '_').toUpperCase()}`] || fallback; }
function command(kind, msg) { process.stdout.write(`::${kind}::${msg.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A')}\n`); }
async function output(name, value) { const p = process.env.GITHUB_OUTPUT; if (p)
    await fs.appendFile(p, `${name}<<CATALOGLOCK_EOF\n${value}\nCATALOGLOCK_EOF\n`); }
async function run() {
    const target = input('target');
    if (!target)
        throw new Error('input target is required');
    const policyPath = input('policy');
    let partial = {};
    if (policyPath)
        partial = JSON.parse(await fs.readFile(policyPath, 'utf8'));
    const failOn = (input('fail-on', partial.failOn ?? 'error'));
    const policy = mergePolicy({ ...partial, failOn });
    const result = await resolveCatalogs(target, { policy });
    const lock = createLockfile(result, policy);
    const lockfile = input('lockfile', 'cataloglock.lock.json');
    await fs.writeFile(lockfile, serializeLockfile(lock));
    const sarif = input('sarif', 'cataloglock.sarif');
    await fs.writeFile(sarif, sarifReport(result.findings));
    const html = input('html', 'cataloglock-report.html');
    await fs.writeFile(html, htmlReport(result));
    const highest = result.findings.reduce((s, f) => severityRank(f.severity) > severityRank(s) ? f.severity : s, 'info');
    await output('highest-severity', highest);
    await output('findings', String(result.findings.length));
    await output('catalogs', String(result.catalogs.length));
    for (const f of result.findings)
        command(f.severity === 'info' ? 'notice' : f.severity === 'warning' ? 'warning' : 'error', `${f.ruleId}: ${f.message}${f.location ? ` (${f.location})` : ''}`);
    if (result.findings.some((f) => severityRank(f.severity) >= severityRank(policy.failOn))) {
        command('error', `CatalogLock policy gate failed at threshold ${policy.failOn}`);
        process.exitCode = 2;
    }
}
run().catch((e) => { command('error', e instanceof Error ? e.message : String(e)); process.exitCode = 1; });
