import test from 'node:test';
import assert from 'node:assert/strict';
import { inspectMcpSurfaces } from '../src/mcp.js';
import { mergePolicy } from '../src/policy.js';
import { createLockfile } from '../src/lockfile.js';
import { diffLockfiles } from '../src/diff.js';
import { auditCatalog } from '../src/audit.js';
import type { FetchResult, ResolveResult } from '../src/types.js';

const catalogUrl='https://example.com/.well-known/ai-catalog.json';
const cardUrl='https://example.com/mcp/server-card';
const endpoint='https://example.com/mcp';
const entry={identifier:'urn:air:example.com:mcp:billing',displayName:'Billing MCP',type:'application/mcp-server-card+json',url:cardUrl};
const resolved:ResolveResult={
  root:catalogUrl,
  catalogs:[{url:catalogUrl,sourceHost:'example.com',sha256:'c'.repeat(64),depth:0,catalog:{specVersion:'0.91',host:{displayName:'Example'},entries:[entry]}}],
  findings:[],
  trust:[{identifier:entry.identifier,sourceCatalog:catalogUrl,publisher:'example.com',publisherMatchesSource:true,entryUrlHost:'example.com',entryUrlWithinPublisher:true,signaturePresent:false,attestations:[],score:70}]
};
const card={name:'com.example/billing',version:'1.0.0',description:'Billing',remotes:[{type:'streamable-http',url:endpoint}]};

function fetcher(): Promise<FetchResult> {
  return Promise.resolve({url:cardUrl,status:200,body:JSON.stringify(card),contentType:'application/mcp-server-card+json'});
}

test('locks a public MCP tools/list surface',async()=>{
  const policy=mergePolicy();
  const requester=async(_url:string,body:unknown,_p:any,headers:Record<string,string>):Promise<FetchResult>=>{
    assert.equal(headers['MCP-Protocol-Version'],'2026-07-28');
    assert.equal(headers['Mcp-Method'],'tools/list');
    assert.equal((body as any).method,'tools/list');
    return {url:endpoint,status:200,body:JSON.stringify({jsonrpc:'2.0',id:1,result:{tools:[
      {name:'get_invoice',description:'Get invoice',inputSchema:{type:'object',properties:{id:{type:'string'}}}}
    ]}})};
  };
  const r=await inspectMcpSurfaces(resolved,policy,{fetcher,requester});
  assert.equal(r.findings.length,0);
  assert.equal(r.surfaces.length,1);
  assert.equal(r.surfaces[0]!.tools[0]!.name,'get_invoice');
  assert.match(r.surfaces[0]!.tools[0]!.toolSha256,/^[a-f0-9]{64}$/);
});

test('supports paginated tools/list and deterministic sorting',async()=>{
  const policy=mergePolicy();
  let calls=0;
  const requester=async(_url:string,body:any):Promise<FetchResult>=>{
    calls++;
    if (!body.params.cursor) return {url:endpoint,status:200,body:JSON.stringify({jsonrpc:'2.0',id:1,result:{tools:[{name:'z_tool',inputSchema:{type:'object'}}],nextCursor:'page2'}})};
    return {url:endpoint,status:200,body:JSON.stringify({jsonrpc:'2.0',id:2,result:{tools:[{name:'a_tool',inputSchema:{type:'object'}}]}})};
  };
  const r=await inspectMcpSurfaces(resolved,policy,{fetcher,requester});
  assert.equal(calls,2);
  assert.deepEqual(r.surfaces[0]!.tools.map(t=>t.name),['a_tool','z_tool']);
});

test('new MCP tool is critical drift even when identity and endpoint are unchanged',async()=>{
  const policy=mergePolicy();
  const requesterA=async():Promise<FetchResult>=>({url:endpoint,status:200,body:JSON.stringify({jsonrpc:'2.0',id:1,result:{tools:[{name:'get_invoice',inputSchema:{type:'object'}}]}})});
  const requesterB=async():Promise<FetchResult>=>({url:endpoint,status:200,body:JSON.stringify({jsonrpc:'2.0',id:1,result:{tools:[
    {name:'get_invoice',inputSchema:{type:'object'}},
    {name:'delete_invoice',inputSchema:{type:'object',properties:{id:{type:'string'}}}}
  ]}})});
  const a=await inspectMcpSurfaces(resolved,policy,{fetcher,requester:requesterA});
  const b=await inspectMcpSurfaces(resolved,policy,{fetcher,requester:requesterB});
  const oldLock=createLockfile({...resolved,mcpSurfaces:a.surfaces},policy);
  const newLock=createLockfile({...resolved,mcpSurfaces:b.surfaces},policy);
  const diff=diffLockfiles(oldLock,newLock);
  assert.equal(diff.blastRadius.addedMcpTools,1);
  assert.equal(diff.blastRadius.highestSeverity,'critical');
  assert.ok(diff.changes.some(c=>c.kind==='mcp-tool-added'&&c.identifier.endsWith('#delete_invoice')));
});

test('tool schema mutation is critical drift',async()=>{
  const policy=mergePolicy();
  const requester=async():Promise<FetchResult>=>({url:endpoint,status:200,body:JSON.stringify({jsonrpc:'2.0',id:1,result:{tools:[{name:'transfer',inputSchema:{type:'object'}}]}})});
  const snap=await inspectMcpSurfaces(resolved,policy,{fetcher,requester});
  const a=createLockfile({...resolved,mcpSurfaces:snap.surfaces},policy);
  const b=structuredClone(a);
  b.mcpSurfaces![0]!.tools[0]!.toolSha256='f'.repeat(64);
  const diff=diffLockfiles(a,b);
  assert.equal(diff.blastRadius.changedMcpTools,1);
  assert.equal(diff.blastRadius.highestSeverity,'critical');
});

test('authenticated server card is warning by default and error when required',async()=>{
  const authCard={...card,remotes:[{type:'streamable-http',url:endpoint,headers:[{name:'Authorization',isRequired:true,isSecret:true}]}]};
  const authFetcher=async():Promise<FetchResult>=>({url:cardUrl,status:200,body:JSON.stringify(authCard)});
  const a=await inspectMcpSurfaces(resolved,mergePolicy(),{fetcher:authFetcher,requester:async()=>{throw new Error('should not call')}});
  assert.equal(a.surfaces.length,0);
  assert.ok(a.findings.some(f=>f.ruleId==='mcp/auth-required'&&f.severity==='warning'));
  const b=await inspectMcpSurfaces(resolved,mergePolicy({requireMcpInspection:true}),{fetcher:authFetcher,requester:async()=>{throw new Error('should not call')}});
  assert.ok(b.findings.some(f=>f.ruleId==='mcp/auth-required'&&f.severity==='error'));
});

test('rejects duplicate tool names and repeated pagination cursor',async()=>{
  const policy=mergePolicy();
  const dup=await inspectMcpSurfaces(resolved,policy,{fetcher,requester:async()=>({url:endpoint,status:200,body:JSON.stringify({jsonrpc:'2.0',id:1,result:{tools:[{name:'x'},{name:'x'}]}})})});
  assert.ok(dup.findings.some(f=>f.ruleId==='mcp/tools-list'&&/duplicate tool/.test(f.message)));
  let call=0;
  const repeat=await inspectMcpSurfaces(resolved,policy,{fetcher,requester:async()=>({url:endpoint,status:200,body:JSON.stringify({jsonrpc:'2.0',id:++call,result:{tools:[],nextCursor:'same'}})})});
  assert.ok(repeat.findings.some(f=>f.ruleId==='mcp/tools-list'&&/repeated pagination cursor/.test(f.message)));
});

test('end-to-end audit follows catalog -> server card -> tools/list -> lockfile',async()=>{
  const policy=mergePolicy();
  const rootBody=JSON.stringify({specVersion:'0.91',host:{displayName:'Example'},entries:[entry]});
  const combinedFetcher=async(url:string):Promise<FetchResult>=>{
    if(url===catalogUrl) return {url,status:200,body:rootBody};
    if(url===cardUrl) return {url,status:200,body:JSON.stringify(card)};
    return {url,status:404,body:''};
  };
  const requester=async():Promise<FetchResult>=>({url:endpoint,status:200,body:JSON.stringify({jsonrpc:'2.0',id:1,result:{tools:[{name:'get_invoice',inputSchema:{type:'object'}}]}})});
  const {result}=await auditCatalog('example.com',{policy,fetcher:combinedFetcher,requester});
  const lock=createLockfile(result,policy);
  assert.equal(result.catalogs.length,1);
  assert.equal(result.mcpSurfaces.length,1);
  assert.equal(lock.lockVersion,2);
  assert.equal(lock.mcpSurfaces?.[0]?.tools[0]?.name,'get_invoice');
});

test('parses SSE data responses from tools/list',async()=>{
  const policy=mergePolicy();
  const requester=async():Promise<FetchResult>=>({url:endpoint,status:200,contentType:'text/event-stream',body:'event: message\ndata: {"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"sse_tool","inputSchema":{"type":"object"}}]}}\n\n'});
  const r=await inspectMcpSurfaces(resolved,policy,{fetcher,requester});
  assert.equal(r.surfaces[0]!.tools[0]!.name,'sse_tool');
});


test('Server Card semantic drift is reported independently of tool drift',async()=>{
  const policy=mergePolicy();
  const requester=async():Promise<FetchResult>=>({url:endpoint,status:200,body:JSON.stringify({jsonrpc:'2.0',id:1,result:{tools:[{name:'get_invoice',inputSchema:{type:'object'}}]}})});
  const snap=await inspectMcpSurfaces(resolved,policy,{fetcher,requester});
  const a=createLockfile({...resolved,mcpSurfaces:snap.surfaces},policy);
  const b=structuredClone(a);
  b.mcpSurfaces![0]!.cardSha256='a'.repeat(64);
  const diff=diffLockfiles(a,b);
  assert.equal(diff.blastRadius.changedMcpCards,1);
  assert.ok(diff.changes.some(c=>c.kind==='mcp-card-changed'&&c.severity==='error'));
});
