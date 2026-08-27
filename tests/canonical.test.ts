import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJson, prettyCanonicalJson, sha256 } from '../src/canonical.js';

test('canonicalJson sorts object keys recursively',()=>assert.equal(canonicalJson({z:1,a:{y:2,x:3}}),'{"a":{"x":3,"y":2},"z":1}'));
test('canonicalJson preserves array order',()=>assert.equal(canonicalJson({a:[3,1,2]}),'{"a":[3,1,2]}'));
test('canonicalJson normalizes negative zero',()=>assert.equal(canonicalJson({n:-0}),'{"n":0}'));
test('canonicalJson rejects NaN',()=>assert.throws(()=>canonicalJson({n:NaN}),/non-finite/));
test('canonicalJson rejects Infinity',()=>assert.throws(()=>canonicalJson({n:Infinity}),/non-finite/));
test('canonicalJson rejects undefined',()=>assert.throws(()=>canonicalJson({x:undefined}),/undefined/));
test('canonicalJson rejects cycles',()=>{const x:any={};x.self=x;assert.throws(()=>canonicalJson(x),/cyclic/);});
test('prettyCanonicalJson ends with deterministic newline',()=>{const s=prettyCanonicalJson({b:1,a:2});assert.ok(s.endsWith('\n'));assert.ok(s.indexOf('"a"')<s.indexOf('"b"'));});
test('sha256 matches known vector',()=>assert.equal(sha256('abc'),'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'));
