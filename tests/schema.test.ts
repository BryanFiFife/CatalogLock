import test from 'node:test';
import assert from 'node:assert/strict';
import { validateCatalog } from '../src/schema.js';
import { mergePolicy } from '../src/policy.js';
const p=mergePolicy();
const good={specVersion:'0.9',host:{displayName:'X'},entries:[{identifier:'urn:air:example.com:agent:x',displayName:'X',type:'application/a2a-agent-card+json',url:'https://example.com/x'}]};
// 23
test('accepts basic catalog shape',()=>{ const r=validateCatalog(good,'https://example.com/.well-known/ai-catalog.json',p); assert.ok(r.catalog); assert.equal(r.findings.length,0); });
// 24
test('rejects non-object catalog',()=>{ const r=validateCatalog([], 'x',p); assert.equal(r.catalog,undefined); assert.equal(r.findings[0]?.severity,'critical'); });
// 25
test('detects duplicate identifiers',()=>{ const r=validateCatalog({...good,entries:[good.entries[0],good.entries[0]]},'x',p); assert.ok(r.findings.some(f=>f.ruleId==='schema/duplicate-identifier')); });
// 26
test('requires exactly one of url/data',()=>{ const e={...good.entries[0],data:{x:1}}; const r=validateCatalog({...good,entries:[e]},'x',p); assert.ok(r.findings.some(f=>f.ruleId==='schema/url-xor-data')); });
// 27
test('flags cleartext resource URL',()=>{ const e={...good.entries[0],url:'http://example.com/x'}; const r=validateCatalog({...good,entries:[e]},'x',p); assert.ok(r.findings.some(f=>f.ruleId==='transport/entry-https')); });
// 28
test('enforces entry count limit',()=>{ const r=validateCatalog({...good,entries:[good.entries[0],{...good.entries[0],identifier:'urn:air:example.com:agent:y'}]},'x',mergePolicy({maxEntriesPerCatalog:1})); assert.ok(r.findings.some(f=>f.ruleId==='limits/entry-count')); });
