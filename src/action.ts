import fs from 'node:fs/promises';
import { auditCatalog } from './audit.js';
import { createLockfile, serializeLockfile } from './lockfile.js';
import { mergePolicy, severityRank } from './policy.js';
import { sarifReport } from './reporters/sarif.js';
import { htmlReport } from './reporters/html.js';
import type { Policy, Severity } from './types.js';

function input(name: string, fallback=''): string {
  return process.env[`INPUT_${name.replace(/ /g,'_').toUpperCase()}`] || fallback;
}
function command(kind:string,msg:string){
  process.stdout.write(`::${kind}::${msg.replace(/%/g,'%25').replace(/\r/g,'%0D').replace(/\n/g,'%0A')}\n`);
}
async function output(name:string,value:string){
  const p=process.env.GITHUB_OUTPUT;
  if(p) await fs.appendFile(p,`${name}<<CATALOGLOCK_EOF\n${value}\nCATALOGLOCK_EOF\n`);
}

async function run(){
  const target=input('target');
  if(!target) throw new Error('input target is required');
  const policyPath=input('policy');
  let partial:Partial<Policy>={};
  if(policyPath) partial=JSON.parse(await fs.readFile(policyPath,'utf8')) as Partial<Policy>;
  const failOn=(input('fail-on',partial.failOn??'error')) as Severity;
  const primitiveFallback = partial.inspectMcpPrimitives ?? partial.inspectMcpTools ?? true;
  const inspectMcpPrimitives=input('inspect-mcp-primitives', String(primitiveFallback)).toLowerCase() !== 'false';
  const inspectMcpDiscover=input('inspect-mcp-discover', String(partial.inspectMcpDiscover ?? true)).toLowerCase() !== 'false';
  const legacyTools=input('inspect-mcp-tools','').trim();
  const effectivePrimitives = legacyTools ? legacyTools.toLowerCase() !== 'false' : inspectMcpPrimitives;
  const policy=mergePolicy({...partial,failOn,inspectMcpPrimitives:effectivePrimitives,inspectMcpDiscover});
  const { result }=await auditCatalog(target,{policy});
  const lock=createLockfile(result,policy);
  const lockfile=input('lockfile','cataloglock.lock.json');
  await fs.writeFile(lockfile,serializeLockfile(lock));
  const sarif=input('sarif','cataloglock.sarif');
  await fs.writeFile(sarif,sarifReport(result.findings));
  const html=input('html','cataloglock-report.html');
  await fs.writeFile(html,htmlReport(result));
  const highest=result.findings.reduce<Severity>((s,f)=>severityRank(f.severity)>severityRank(s)?f.severity:s,'info');
  const count=(key:'tools'|'prompts'|'resources'|'resourceTemplates')=>result.mcpSurfaces.reduce((n,s)=>n+(s[key]?.items.length??0),0);
  await output('highest-severity',highest);
  await output('findings',String(result.findings.length));
  await output('catalogs',String(result.catalogs.length));
  await output('mcp-surfaces',String(result.mcpSurfaces.length));
  await output('mcp-tools',String(count('tools')));
  await output('mcp-prompts',String(count('prompts')));
  await output('mcp-resources',String(count('resources')));
  await output('mcp-resource-templates',String(count('resourceTemplates')));
  for(const f of result.findings) command(f.severity==='info'?'notice':f.severity==='warning'?'warning':'error',`${f.ruleId}: ${f.message}${f.location?` (${f.location})`:''}`);
  if(result.findings.some(f=>severityRank(f.severity)>=severityRank(policy.failOn))) {
    command('error',`CatalogLock policy gate failed at threshold ${policy.failOn}`);
    process.exitCode=2;
  }
}
run().catch(e=>{command('error',e instanceof Error?e.message:String(e));process.exitCode=1});
