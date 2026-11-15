import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

const rules = fs.readFileSync('firestore.rules', 'utf8');
const blueprint = JSON.parse(fs.readFileSync('firebase-blueprint.json', 'utf8'));

test('firestore.rules uses rules_version 2 and default-deny catch-all', () => {
  assert.match(rules, /rules_version\s*=\s*'2'/);
  assert.match(rules, /match\s*\/\{document=\*\*\}\s*\{\s*allow\s+read,\s*write:\s*if\s+false;\s*\}/);
});

test('firestore.rules covers every collection defined in firebase-blueprint.json', () => {
  assert.ok(blueprint.firestore['/users/{userId}']);
  assert.ok(blueprint.firestore['/users/{userId}/devices/{deviceId}']);
  assert.ok(blueprint.firestore['/conversations/{conversationId}']);
  assert.ok(blueprint.firestore['/conversations/{conversationId}/messages/{messageId}']);

  assert.match(rules, /match\s+\/users\/\{userId\}/);
  assert.match(rules, /match\s+\/devices\/\{deviceId\}/);
  assert.match(rules, /match\s+\/conversations\/\{conversationId\}/);
  assert.match(rules, /match\s+\/messages\/\{messageId\}/);
});

test('firestore.rules enforces Dirty Dozen invariants: verified email, strict keys, no get() in list, terminal locking', () => {
  assert.match(rules, /request\.auth\.token\.email_verified\s*==\s*true/);
  assert.match(rules, /data\.keys\(\)\.hasAll/);
  assert.match(rules, /data\.keys\(\)\.hasOnly/);
  assert.match(rules, /data\.creatorUid\s*!=\s*data\.peerUid/);
  assert.match(rules, /existing\(\)\.status\s*==\s*'active'/);
  assert.match(rules, /existing\(\)\.status\s*!=\s*'expired'/);
  assert.match(rules, /incoming\(\)\.createdAt\s*==\s*request\.time/);

  // Ensure allow list blocks do not call get() or exists()
  const listBlocks = [...rules.matchAll(/allow list:[^;]+;/g)].map((m) => m[0]);
  assert.ok(listBlocks.length >= 4);
  for (const block of listBlocks) {
    assert.equal(/\b(get|exists)\(/.test(block), false, `allow list must not use get()/exists(): ${block}`);
  }
});
