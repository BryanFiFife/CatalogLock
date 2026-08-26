import test from 'node:test';
import assert from 'node:assert/strict';
import { DEFAULT_POLICY, mergePolicy, policyFingerprint, severityRank } from '../src/policy.js';

// 5
test('mergePolicy returns secure defaults',()=>{ const p=mergePolicy(); assert.equal(p.allowHttp,false); assert.deepEqual(p.allowedPorts,[443]); });
// 6
test('mergePolicy overrides a field',()=>{ assert.equal(mergePolicy({maxDepth:2}).maxDepth,2); });
// 7
test('mergePolicy rejects invalid depth',()=>{ assert.throws(()=>mergePolicy({maxDepth:99}),/maxDepth/); });
// 8
test('mergePolicy rejects invalid ports',()=>{ assert.throws(()=>mergePolicy({allowedPorts:[0]}),/allowedPorts/); });
// 9
test('policy fingerprint changes when policy changes',()=>{ assert.notEqual(policyFingerprint(DEFAULT_POLICY),policyFingerprint({...DEFAULT_POLICY,maxDepth:3})); });
// 10
test('severity ranks critical highest',()=>{ assert.ok(severityRank('critical')>severityRank('error')); assert.ok(severityRank('error')>severityRank('warning')); });
