import test from 'node:test';
import assert from 'node:assert/strict';
import { createLockfile, serializeLockfile, VERSION } from '../src/lockfile.js';
import { diffLockfiles } from '../src/diff.js';
import { mergePolicy } from '../src/policy.js';
import type { ResolveResult } from '../src/types.js';

const entry={identifier:'urn:air:example.com:agent:a',displayName:'A',type:'application/a2a-agent-card+json',url:'https://api.example.com/a',representativeQueries:['one','two']};
const resolved:ResolveResult={root:'https://example.com/.well-known/ard.json',rootSourceKind:'ard',ardContextSha256:'a'.repeat(64),catalogs:[{url:'https://example.com/.well-known/ard.json',sourceHost:'example.com',sha256:'b'.repeat(64),depth:0,catalog:{entries:[entry]}}],findings:[],trust:[{identifier:entry.identifier,sourceCatalog:'https://example.com/.well-known/ard.json',publisher:'example.com',publisherMatchesSource:true,entryUrlHost:'api.example.com',entryUrlWithinPublisher:true,identity:'https://example.com',identityMatchesPublisher:true,signaturePresent:true,attestations:[],state:'verified',verifiedEvidenceDigests:['jws:x'],trustEvidenceSha256:'c'.repeat(64),score:100}]};
const p=mergePolicy({inspectMcpPrimitives:false,inspectMcpDiscover:false});

test('version is 0.3.0',()=>assert.equal(VERSION,'0.3.0'));
test('lockfile v3 captures ARD resolution and trust state',()=>{const l=createLockfile(resolved,p);assert.equal(l.lockVersion,3);assert.equal(l.rootSourceKind,'ard');assert.equal(l.ardContextSha256,'a'.repeat(64));assert.equal(l.catalogs[0]!.entries[0]!.trustState,'verified');});
test('lockfile serialization is deterministic',()=>assert.equal(serializeLockfile(createLockfile(resolved,p)),serializeLockfile(createLockfile(resolved,p))));
test('graph hash includes root source kind',()=>{const a=createLockfile(resolved,p);const b=createLockfile({...resolved,rootSourceKind:'rel-ard'},p);assert.notEqual(a.graphSha256,b.graphSha256);});
test('root source drift is classified',()=>{const a=createLockfile(resolved,p);const b=createLockfile({...resolved,rootSourceKind:'rel-ard'},p);assert.ok(diffLockfiles(a,b).changes.some(c=>c.kind==='root-source-changed'));});
test('ARD context drift is critical',()=>{const a=createLockfile(resolved,p);const b=structuredClone(a);b.ardContextSha256='d'.repeat(64);assert.ok(diffLockfiles(a,b).changes.some(c=>c.kind==='ard-context-changed'&&c.severity==='critical'));});
test('verified trust regression is critical',()=>{const a=createLockfile(resolved,p);const b=structuredClone(a);b.catalogs[0]!.entries[0]!.trustState='present-unverified';assert.ok(diffLockfiles(a,b).changes.some(c=>c.kind==='trust-regressed'&&c.severity==='critical'));});
test('trust evidence rotation is visible even at same state',()=>{const a=createLockfile(resolved,p);const b=structuredClone(a);b.catalogs[0]!.entries[0]!.trustEvidenceSha256='e'.repeat(64);assert.ok(diffLockfiles(a,b).changes.some(c=>c.kind==='trust-changed'));});
test('resource definition change remains explicit',()=>{const a=createLockfile(resolved,p);const b=structuredClone(a);b.catalogs[0]!.entries[0]!.entrySha256='e'.repeat(64);assert.ok(diffLockfiles(a,b).changes.some(c=>c.kind==='resource-changed'));});
test('catalog body drift remains explicit',()=>{const a=createLockfile(resolved,p);const b=structuredClone(a);b.catalogs[0]!.sha256='e'.repeat(64);assert.ok(diffLockfiles(a,b).changes.some(c=>c.kind==='catalog-changed'));});
test('policy drift remains explicit',()=>{const a=createLockfile(resolved,p);const b=structuredClone(a);b.policySha256='e'.repeat(64);assert.ok(diffLockfiles(a,b).changes.some(c=>c.kind==='policy-changed'));});
