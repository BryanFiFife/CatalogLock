import test from 'node:test';
import assert from 'node:assert/strict';
import { isPublicIp, targetToCandidateUrls, validateOutboundUrl } from '../src/net.js';
import { mergePolicy } from '../src/policy.js';

const p=mergePolicy();
// 11
test('rejects loopback IPv4',()=>assert.equal(isPublicIp('127.0.0.1'),false));
// 12
test('rejects RFC1918 IPv4',()=>{ assert.equal(isPublicIp('10.0.0.1'),false); assert.equal(isPublicIp('172.16.4.5'),false); assert.equal(isPublicIp('192.168.1.2'),false); });
// 13
test('rejects link-local and metadata IPv4',()=>assert.equal(isPublicIp('169.254.169.254'),false));
// 14
test('rejects documentation ranges',()=>{ assert.equal(isPublicIp('192.0.2.1'),false); assert.equal(isPublicIp('198.51.100.2'),false); assert.equal(isPublicIp('203.0.113.4'),false); });
// 15
test('accepts ordinary public IPv4',()=>assert.equal(isPublicIp('8.8.8.8'),true));
// 16
test('rejects IPv6 loopback and ULA',()=>{ assert.equal(isPublicIp('::1'),false); assert.equal(isPublicIp('fd00::1'),false); });
// 17
test('accepts ordinary public IPv6',()=>assert.equal(isPublicIp('2606:4700:4700::1111'),true));
// 18
test('validateOutboundUrl rejects http by default',()=>assert.throws(()=>validateOutboundUrl('http://example.com/x',p),/protocol/));
// 19
test('validateOutboundUrl rejects embedded credentials',()=>assert.throws(()=>validateOutboundUrl('https://u:p@example.com/x',p),/credentials/));
// 20
test('validateOutboundUrl rejects non-allowlisted port',()=>assert.throws(()=>validateOutboundUrl('https://example.com:8443/x',p),/port/));
// 21
test('target domain maps to canonical ARD path first',()=>{ const urls=targetToCandidateUrls('example.com',p); assert.equal(urls[0],'https://example.com/.well-known/ai-catalog.json'); assert.equal(urls[1],'https://example.com/.well-known/ard.json'); });
// 22
test('explicit catalog URL is preserved',()=>{ assert.deepEqual(targetToCandidateUrls('https://example.com/custom/catalog.json',p),['https://example.com/custom/catalog.json']); });
