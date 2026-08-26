import fs from 'node:fs/promises';
import path from 'node:path';
import { resolveCatalogs } from './resolver.js';
import { createLockfile, serializeLockfile, VERSION } from './lockfile.js';
import { diffLockfiles } from './diff.js';
import { htmlReport } from './reporters/html.js';
import { sarifReport } from './reporters/sarif.js';
import { jsonReport } from './reporters/json.js';
import { mergePolicy, severityRank } from './policy.js';
import type { CatalogLockfile, Policy, Severity } from './types.js';

interface Args { _: string[]; [key: string]: string | boolean | string[]; }
function parseArgs(argv: string[]): Args {
  const out: Args = { _: [] };
  for (let i=0;i<argv.length;i++) {
    const a=argv[i]!;
    if (!a.startsWith('--')) { out._.push(a); continue; }
    const [rawKey, inline] = a.slice(2).split('=',2); const key=rawKey!;
    if (inline !== undefined) { out[key]=inline; continue; }
    const next=argv[i+1];
    if (next && !next.startsWith('--')) { out[key]=next; i++; } else out[key]=true;
  }
  return out;
}
function help(): string { return `CatalogLock ${VERSION}\n\nUsage:\n  cataloglock scan <domain|catalog-url> [--format json|html|sarif] [--output FILE] [--policy FILE] [--fail-on LEVEL]\n  cataloglock lock <domain|catalog-url> [--output cataloglock.lock.json] [--policy FILE]\n  cataloglock diff <old.lock.json> <new.lock.json> [--format text|json]\n  cataloglock verify <domain|catalog-url> --lock cataloglock.lock.json [--policy FILE]\n\nLevels: info, warning, error, critical\n` }
async function readPolicy(file?: string): Promise<Policy> {
  if (!file) return mergePolicy();
  return mergePolicy(JSON.parse(await fs.readFile(file,'utf8')) as Partial<Policy>);
}
function setFailOn(policy: Policy, value: unknown): Policy {
  if (typeof value !== 'string') return policy;
  if (!['info','warning','error','critical'].includes(value)) throw new Error(`invalid --fail-on ${value}`);
  return { ...policy, failOn: value as Severity };
}
function shouldFail(findings: {severity: Severity}[], threshold: Severity): boolean { return findings.some((f)=>severityRank(f.severity)>=severityRank(threshold)); }
async function writeOrStdout(content: string, file?: unknown): Promise<void> { if (typeof file === 'string') { await fs.mkdir(path.dirname(path.resolve(file)),{recursive:true}); await fs.writeFile(file,content); } else process.stdout.write(content); }

export async function main(argv=process.argv.slice(2)): Promise<number> {
  const args=parseArgs(argv); const command=args._[0];
  if (args.version===true || command==='--version' || command==='version') { process.stdout.write(`${VERSION}\n`); return 0; }
  if (!command || command==='help' || args.help===true) { process.stdout.write(help()); return 0; }
  if (command==='scan' || command==='lock' || command==='verify') {
    const target=args._[1]; if (!target) throw new Error(`${command} requires a target`);
    let policy=await readPolicy(typeof args.policy==='string'?args.policy:undefined); policy=setFailOn(policy,args['fail-on']);
    const result=await resolveCatalogs(target,{policy});
    if (command==='scan') {
      const format=typeof args.format==='string'?args.format:'json';
      if (!['json','html','sarif'].includes(format)) throw new Error(`unsupported scan format: ${format}`);
      const content=format==='html'?htmlReport(result):format==='sarif'?sarifReport(result.findings):jsonReport(result);
      await writeOrStdout(content,args.output); return shouldFail(result.findings,policy.failOn)?2:0;
    }
    const lock=createLockfile(result,policy);
    if (command==='lock') { await writeOrStdout(serializeLockfile(lock), typeof args.output==='string'?args.output:'cataloglock.lock.json'); return shouldFail(result.findings,policy.failOn)?2:0; }
    const lockPath=typeof args.lock==='string'?args.lock:'cataloglock.lock.json'; const old=JSON.parse(await fs.readFile(lockPath,'utf8')) as CatalogLockfile; const diff=diffLockfiles(old,lock); await writeOrStdout(jsonReport(diff),args.output); return diff.changed||shouldFail(result.findings,policy.failOn)?3:0;
  }
  if (command==='diff') {
    const a=args._[1],b=args._[2]; if(!a||!b) throw new Error('diff requires two lockfiles');
    const old=JSON.parse(await fs.readFile(a,'utf8')) as CatalogLockfile; const cur=JSON.parse(await fs.readFile(b,'utf8')) as CatalogLockfile; const diff=diffLockfiles(old,cur);
    if (args.format !== undefined && args.format !== 'json' && args.format !== 'text') throw new Error(`unsupported diff format: ${String(args.format)}`);
    if (args.format==='json') await writeOrStdout(jsonReport(diff),args.output);
    else { const lines=[`CatalogLock diff: ${diff.changed?'CHANGED':'clean'}`,`Blast radius: ${JSON.stringify(diff.blastRadius)}`,...diff.changes.map((c)=>`[${c.severity.toUpperCase()}] ${c.kind}: ${c.message}`)]; await writeOrStdout(lines.join('\n')+'\n',args.output); }
    return diff.changed?3:0;
  }
  throw new Error(`unknown command: ${command}`);
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('cli.cjs')) {
  main().then((code)=>{process.exitCode=code}).catch((err)=>{console.error(`cataloglock: ${err instanceof Error?err.message:String(err)}`);process.exitCode=1});
}
