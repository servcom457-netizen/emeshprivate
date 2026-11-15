import test from 'node:test';
import assert from 'node:assert/strict';
import {
  computeJointSafetyNumber,
  createDeviceIdentity,
  decryptEnvelope,
  decryptFileBytes,
  encryptEnvelope,
  encryptFileBytes,
  toPublicIdentity,
  unwrapIdentityWithPin,
  wrapIdentityWithPin,
} from './emeshCrypto';

test('PIN wrapping protects private keys and rejects wrong PIN', async () => {
  const alice = await createDeviceIdentity('Alice');
  const wrapped = await wrapIdentityWithPin(alice, '4829');

  // Wrapped bundle must not expose private key coordinates in plaintext
  assert.equal(wrapped.wrappedPrivateBundleB64.includes(alice.identityPrivateKey.d ?? 'impossible'), false);

  const unlocked = await unwrapIdentityWithPin(wrapped, '4829');
  assert.equal(unlocked.deviceId, alice.deviceId);
  assert.equal(unlocked.identityPrivateKey.d, alice.identityPrivateKey.d);

  await assert.rejects(() => unwrapIdentityWithPin(wrapped, '0000'), /Code PIN incorrect/);
});

test('E2EE encryptEnvelope & decryptEnvelope work between Alice and Bob and block Eve/tampering', async () => {
  const alice = await createDeviceIdentity('Alice');
  const bob = await createDeviceIdentity('Bob');
  const eve = await createDeviceIdentity('Eve');

  const alicePub = toPublicIdentity(alice);
  const bobPub = toPublicIdentity(bob);

  // Joint safety number is symmetric
  const snAlice = await computeJointSafetyNumber(alicePub, bobPub);
  const snBob = await computeJointSafetyNumber(bobPub, alicePub);
  assert.equal(snAlice, snBob);

  const envelope = await encryptEnvelope({
    sender: alice,
    peer: bobPub,
    conversationId: 'conv_test_1',
    messageType: 'text',
    payload: {
      text: 'Rendez-vous secret à 21h.',
      nonce: 'n1',
      sentAt: 1700000000000,
    },
    ephemeralTtlMs: 30000,
    keyEpoch: 1,
    ratchetCounter: 1,
  });

  // Server sees only ciphertext, never plaintext
  assert.equal(envelope.ciphertext.includes('Rendez-vous'), false);

  // Bob decrypts successfully
  const decrypted = await decryptEnvelope({
    receiver: bob,
    peer: alicePub,
    envelope,
  });
  assert.equal(decrypted.verifiedSignature, true);
  assert.equal(decrypted.payload.text, 'Rendez-vous secret à 21h.');

  // Eve (3rd party) cannot decrypt the envelope
  await assert.rejects(() =>
    decryptEnvelope({
      receiver: eve,
      peer: alicePub,
      envelope,
    })
  );

  // Tampered ciphertext / counter fails signature or AAD check
  const tampered = { ...envelope, ratchetCounter: 99 };
  await assert.rejects(() =>
    decryptEnvelope({
      receiver: bob,
      peer: alicePub,
      envelope: tampered,
    })
  );
});

test('Photos, videos, audio, and documents are encrypted before transmission and decrypted identically', async () => {
  const rawPhotoBytes = new Uint8Array([137, 80, 78, 71, 13, 10, 26, 10, 99, 100, 101, 102]);
  const { encryptedBytes, fileKeyB64, fileIvB64 } = await encryptFileBytes(rawPhotoBytes);

  // Encrypted blob differs from raw PNG header
  assert.notDeepEqual(Array.from(encryptedBytes.slice(0, 4)), [137, 80, 78, 71]);

  const decryptedBytes = await decryptFileBytes(encryptedBytes, fileKeyB64, fileIvB64);
  assert.deepEqual(Array.from(decryptedBytes), Array.from(rawPhotoBytes));
});
