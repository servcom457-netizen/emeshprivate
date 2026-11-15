import test from 'node:test';
import assert from 'node:assert/strict';
import { EmeshSecurityStore } from './securityStore';
import {
  createDeviceIdentity,
  decryptEnvelope,
  encryptEnvelope,
  toPublicIdentity,
} from '../src/crypto/emeshCrypto';

async function setupRegisteredDevice(store: EmeshSecurityStore, name: string) {
  const id = await createDeviceIdentity(name);
  const pub = toPublicIdentity(id);
  await store.registerDevice({
    deviceId: pub.deviceId,
    pseudonym: pub.pseudonym,
    identityPublicKey: pub.identityPublicKey,
    signingPublicKey: pub.signingPublicKey,
    fingerprint: pub.fingerprint,
  });
  return { id, pub };
}

test('Two users can pair with a >=8 char single-use code, and third party is blocked', async () => {
  const store = new EmeshSecurityStore();
  const alice = await setupRegisteredDevice(store, 'Alice');
  const bob = await setupRegisteredDevice(store, 'Bob');
  const eve = await setupRegisteredDevice(store, 'Eve');

  const t0 = 1_700_000_000_000;
  const { code, expiresAt } = store.createPairingCode(alice.pub.deviceId, t0);
  assert.ok(code.replace(/-/g, '').length >= 8);
  assert.equal(expiresAt, t0 + 10 * 60 * 1000);

  // Bob redeems the code
  const paired = store.redeemPairingCode(bob.pub.deviceId, code, bob.pub.deviceId, t0 + 1000);
  assert.deepEqual(paired.conversation.participants, [alice.pub.deviceId, bob.pub.deviceId]);

  // Code cannot be reused by Eve
  assert.throws(
    () => store.redeemPairingCode(eve.pub.deviceId, code, eve.pub.deviceId, t0 + 2000),
    /introuvable ou déjà invalidé|déjà été utilisé/
  );

  // Eve cannot access Alice & Bob's conversation or messages
  assert.throws(
    () => store.getMessagesForConversation(paired.conversation.conversationId, eve.pub.deviceId),
    /Accès refusé/
  );
  assert.equal(store.listConversationsForDevice(eve.pub.deviceId).length, 0);
});

test('Expired pairing code fails after 10 minutes', async () => {
  const store = new EmeshSecurityStore();
  const alice = await setupRegisteredDevice(store, 'Alice');
  const bob = await setupRegisteredDevice(store, 'Bob');

  const t0 = 1_700_000_000_000;
  const { code } = store.createPairingCode(alice.pub.deviceId, t0);

  assert.throws(
    () =>
      store.redeemPairingCode(
        bob.pub.deviceId,
        code,
        bob.pub.deviceId,
        t0 + 10 * 60 * 1000 + 1
      ),
    /expiré/
  );
});

test('Rate limiting blocks repeated pairing code brute-force attempts', async () => {
  const store = new EmeshSecurityStore();
  const attacker = await setupRegisteredDevice(store, 'Attacker');
  const t0 = 1_700_000_000_000;

  for (let i = 0; i < 5; i++) {
    assert.throws(
      () => store.redeemPairingCode(attacker.pub.deviceId, `WRONG0000${i}`, 'ip:1.2.3.4', t0 + i * 100),
      /introuvable/
    );
  }
  assert.throws(
    () => store.redeemPairingCode(attacker.pub.deviceId, 'WRONG99999', 'ip:1.2.3.4', t0 + 600),
    /Trop de tentatives/
  );
});

test('Unread messages persist until read, then expire according to configured ephemeral TTL', async () => {
  const store = new EmeshSecurityStore();
  const alice = await setupRegisteredDevice(store, 'Alice');
  const bob = await setupRegisteredDevice(store, 'Bob');

  const t0 = 1_700_000_000_000;
  const { code } = store.createPairingCode(alice.pub.deviceId, t0);
  const { conversation } = store.redeemPairingCode(bob.pub.deviceId, code, bob.pub.deviceId, t0 + 500);

  const envelope = await encryptEnvelope({
    sender: alice.id,
    peer: bob.pub,
    conversationId: conversation.conversationId,
    messageType: 'text',
    payload: { text: 'Message éphémère 10s', nonce: 'abc', sentAt: t0 + 1000 },
    ephemeralTtlMs: 10000,
    keyEpoch: 1,
    ratchetCounter: 1,
  });

  // Server never holds plaintext
  const stored = store.storeEncryptedMessage(alice.pub.deviceId, envelope, t0 + 1000);
  assert.equal(JSON.stringify(stored).includes('Message éphémère'), false);

  // Sweep 1 hour later while UNREAD -> must NOT delete unread message prematurely
  const sweepUnread = store.sweepExpired(t0 + 3_600_000);
  assert.equal(sweepUnread.expiredMessages.length, 0);
  assert.equal(store.getMessagesForConversation(conversation.conversationId, bob.pub.deviceId).length, 1);

  // Bob decrypts and marks as read at tRead
  const decrypted = await decryptEnvelope({ receiver: bob.id, peer: alice.pub, envelope: stored });
  assert.equal(decrypted.payload.text, 'Message éphémère 10s');

  const tRead = t0 + 3_600_000;
  const readRes = store.markMessageRead(conversation.conversationId, stored.messageId, bob.pub.deviceId, tRead);
  assert.equal(readRes?.expiredImmediately, false);

  // At tRead + 9_999ms -> still present
  assert.equal(store.sweepExpired(tRead + 9999).expiredMessages.length, 0);
  // At tRead + 10_000ms -> purged from server
  const sweepAfter = store.sweepExpired(tRead + 10000);
  assert.equal(sweepAfter.expiredMessages.length, 1);
  assert.equal(store.getMessagesForConversation(conversation.conversationId, bob.pub.deviceId).length, 0);
});

test('Instant-destruct (0ms) message purges immediately upon read receipt', async () => {
  const store = new EmeshSecurityStore();
  const alice = await setupRegisteredDevice(store, 'Alice');
  const bob = await setupRegisteredDevice(store, 'Bob');

  const t0 = 1_700_000_000_000;
  const { code } = store.createPairingCode(alice.pub.deviceId, t0);
  const { conversation } = store.redeemPairingCode(bob.pub.deviceId, code, bob.pub.deviceId, t0 + 100);

  const envelope = await encryptEnvelope({
    sender: alice.id,
    peer: bob.pub,
    conversationId: conversation.conversationId,
    messageType: 'text',
    payload: { text: 'Lecture unique', nonce: 'xyz', sentAt: t0 + 200 },
    ephemeralTtlMs: 0,
    keyEpoch: 1,
    ratchetCounter: 1,
  });

  const stored = store.storeEncryptedMessage(alice.pub.deviceId, envelope, t0 + 200);
  const readRes = store.markMessageRead(conversation.conversationId, stored.messageId, bob.pub.deviceId, t0 + 500);
  assert.equal(readRes?.expiredImmediately, true);
  assert.equal(store.getMessagesForConversation(conversation.conversationId, bob.pub.deviceId).length, 0);
});
