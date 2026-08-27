import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalJson, prettyCanonicalJson, sha256 } from '../src/canonical.js';

test('canonicalJson sorts object keys recursively', () => {
  assert.equal(canonicalJson({z:1,a:{y:2,x:3}}), '{"a":{"x":3,"y":2},"z":1}');
});
test('canonicalJson preserves array order', () => {
  assert.equal(canonicalJson({a:[3,1,2]}), '{"a":[3,1,2]}');
});
test('prettyCanonicalJson has deterministic trailing newline', () => {
  const s=prettyCanonicalJson({b:1,a:2}); assert.ok(s.endsWith('\n')); assert.ok(s.indexOf('"a"')<s.indexOf('"b"'));
});
test('sha256 is stable', () => {
  assert.equal(sha256('abc'),'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
});
