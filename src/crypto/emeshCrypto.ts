import type {
  DecryptedPayload,
  EncryptedEnvelope,
  EphemeralDurationMs,
  MessageType,
  PublicIdentity,
  UnlockedIdentity,
  WrappedVaultRecord,
} from '../types';

function getSubtle(): SubtleCrypto {
  const cryptoObj = globalThis.crypto;
  if (!cryptoObj || !cryptoObj.subtle) {
    throw new Error('WebCrypto API indisponible dans cet environnement.');
  }
  return cryptoObj.subtle;
}

export function randomBytes(length: number): Uint8Array {
  const bytes = new Uint8Array(length);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

export function bytesToBase64(bytes: Uint8Array): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(bytes).toString('base64');
  }
  let binary = '';
  const chunkSize = 0x8000;
  for (let i = 0; i < bytes.length; i += chunkSize) {
    const slice = bytes.subarray(i, i + chunkSize);
    binary += String.fromCharCode(...slice);
  }
  return btoa(binary);
}

export function base64ToBytes(b64: string): Uint8Array {
  if (typeof Buffer !== 'undefined') {
    return new Uint8Array(Buffer.from(b64, 'base64'));
  }
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export function generateId(prefix = 'em'): string {
  return `${prefix}_${bytesToHex(randomBytes(12))}`;
}

function canonicalPublicKeyString(jwk: JsonWebKey): string {
  return JSON.stringify({
    crv: jwk.crv,
    kty: jwk.kty,
    x: jwk.x,
    y: jwk.y,
  });
}

export async function computeIdentityFingerprint(
  identityPub: JsonWebKey,
  signingPub: JsonWebKey
): Promise<string> {
  const subtle = getSubtle();
  const encoder = new TextEncoder();
  const data = encoder.encode(
    `eMesh-fp-v1|${canonicalPublicKeyString(identityPub)}|${canonicalPublicKeyString(signingPub)}`
  );
  const hash = new Uint8Array(await subtle.digest('SHA-256', data));
  const hex = bytesToHex(hash).toUpperCase();
  const groups: string[] = [];
  for (let i = 0; i < 48; i += 4) {
    groups.push(hex.slice(i, i + 4));
  }
  return groups.join(' ');
}

export async function computeJointSafetyNumber(
  local: PublicIdentity,
  peer: PublicIdentity
): Promise<string> {
  const subtle = getSubtle();
  const encoder = new TextEncoder();
  const ordered = [local, peer].sort((a, b) => a.deviceId.localeCompare(b.deviceId));
  const payload = ordered
    .map((p) => `${p.deviceId}|${p.identityPublicKey}|${p.signingPublicKey}`)
    .join('||');
  const hash = new Uint8Array(await subtle.digest('SHA-256', encoder.encode(`eMesh-safety-v1|${payload}`)));
  // Convert 30 bytes into 12 groups of 5 decimal digits (60 digits total)
  const blocks: string[] = [];
  for (let i = 0; i < 24; i += 2) {
    const val = ((hash[i] << 8) | hash[i + 1]) % 100000;
    blocks.push(String(val).padStart(5, '0'));
  }
  return blocks.join(' ');
}

export async function createDeviceIdentity(pseudonym: string): Promise<UnlockedIdentity> {
  const subtle = getSubtle();
  const cleanPseudo = pseudonym.trim();
  if (cleanPseudo.length < 2 || cleanPseudo.length > 40) {
    throw new Error('Le pseudonyme doit contenir entre 2 et 40 caractères.');
  }

  const identityPair = await subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );

  const signingPair = await subtle.generateKey(
    { name: 'ECDSA', namedCurve: 'P-256' },
    true,
    ['sign', 'verify']
  );

  const identityPublicKey = await subtle.exportKey('jwk', identityPair.publicKey);
  const identityPrivateKey = await subtle.exportKey('jwk', identityPair.privateKey);
  const signingPublicKey = await subtle.exportKey('jwk', signingPair.publicKey);
  const signingPrivateKey = await subtle.exportKey('jwk', signingPair.privateKey);

  const fingerprint = await computeIdentityFingerprint(identityPublicKey, signingPublicKey);

  return {
    deviceId: generateId('dev'),
    pseudonym: cleanPseudo,
    identityPublicKey,
    identityPrivateKey,
    signingPublicKey,
    signingPrivateKey,
    fingerprint,
    createdAt: Date.now(),
  };
}

export function toPublicIdentity(identity: UnlockedIdentity): PublicIdentity {
  return {
    deviceId: identity.deviceId,
    pseudonym: identity.pseudonym,
    identityPublicKey: canonicalPublicKeyString(identity.identityPublicKey),
    signingPublicKey: canonicalPublicKeyString(identity.signingPublicKey),
    fingerprint: identity.fingerprint,
  };
}

async function derivePinKey(pin: string, salt: Uint8Array): Promise<CryptoKey> {
  const subtle = getSubtle();
  const encoder = new TextEncoder();
  const baseKey = await subtle.importKey('raw', encoder.encode(pin), 'PBKDF2', false, [
    'deriveKey',
  ]);
  return subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt.buffer as ArrayBuffer,
      iterations: 210000,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function wrapIdentityWithPin(
  identity: UnlockedIdentity,
  pin: string
): Promise<WrappedVaultRecord> {
  if (!/^\d{4,8}$/.test(pin)) {
    throw new Error('Le code PIN doit contenir entre 4 et 8 chiffres.');
  }
  const subtle = getSubtle();
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const pinKey = await derivePinKey(pin, salt);
  const secretBundle = JSON.stringify({
    identityPrivateKey: identity.identityPrivateKey,
    signingPrivateKey: identity.signingPrivateKey,
  });
  const ciphertext = new Uint8Array(
    await subtle.encrypt(
      { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
      pinKey,
      new TextEncoder().encode(secretBundle)
    )
  );

  return {
    deviceId: identity.deviceId,
    pseudonym: identity.pseudonym,
    identityPublicKey: identity.identityPublicKey,
    signingPublicKey: identity.signingPublicKey,
    fingerprint: identity.fingerprint,
    saltB64: bytesToBase64(salt),
    ivB64: bytesToBase64(iv),
    wrappedPrivateBundleB64: bytesToBase64(ciphertext),
    createdAt: identity.createdAt,
  };
}

export async function unwrapIdentityWithPin(
  vault: WrappedVaultRecord,
  pin: string
): Promise<UnlockedIdentity> {
  const subtle = getSubtle();
  const salt = base64ToBytes(vault.saltB64);
  const iv = base64ToBytes(vault.ivB64);
  const ciphertext = base64ToBytes(vault.wrappedPrivateBundleB64);
  const pinKey = await derivePinKey(pin, salt);

  try {
    const plaintext = await subtle.decrypt(
      { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
      pinKey,
      ciphertext.buffer as ArrayBuffer
    );
    const parsed = JSON.parse(new TextDecoder().decode(plaintext)) as {
      identityPrivateKey: JsonWebKey;
      signingPrivateKey: JsonWebKey;
    };
    return {
      deviceId: vault.deviceId,
      pseudonym: vault.pseudonym,
      identityPublicKey: vault.identityPublicKey,
      identityPrivateKey: parsed.identityPrivateKey,
      signingPublicKey: vault.signingPublicKey,
      signingPrivateKey: parsed.signingPrivateKey,
      fingerprint: vault.fingerprint,
      createdAt: vault.createdAt,
    };
  } catch {
    throw new Error('Code PIN incorrect.');
  }
}

export async function signWithDevice(
  signingPrivateKeyJwk: JsonWebKey,
  payload: string
): Promise<string> {
  const subtle = getSubtle();
  const key = await subtle.importKey(
    'jwk',
    signingPrivateKeyJwk,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['sign']
  );
  const sig = await subtle.sign(
    { name: 'ECDSA', hash: 'SHA-256' },
    key,
    new TextEncoder().encode(payload)
  );
  return bytesToBase64(new Uint8Array(sig));
}

export async function verifyDeviceSignature(
  signingPublicKeyJson: string,
  payload: string,
  signatureB64: string
): Promise<boolean> {
  try {
    const subtle = getSubtle();
    const pubJwk = JSON.parse(signingPublicKeyJson) as JsonWebKey;
    const key = await subtle.importKey(
      'jwk',
      pubJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    return subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      key,
      base64ToBytes(signatureB64).buffer as ArrayBuffer,
      new TextEncoder().encode(payload)
    );
  } catch {
    return false;
  }
}

async function deriveConversationRootBits(
  myIdentityPrivJwk: JsonWebKey,
  peerIdentityPubJson: string
): Promise<ArrayBuffer> {
  const subtle = getSubtle();
  const privKey = await subtle.importKey(
    'jwk',
    myIdentityPrivJwk,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits']
  );
  const peerPubKey = await subtle.importKey(
    'jwk',
    JSON.parse(peerIdentityPubJson) as JsonWebKey,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );
  return subtle.deriveBits({ name: 'ECDH', public: peerPubKey }, privKey, 256);
}

async function deriveMessageAesKey(params: {
  rootBits: ArrayBuffer;
  ephemeralBits: ArrayBuffer;
  conversationId: string;
  senderDeviceId: string;
  keyEpoch: number;
  ratchetCounter: number;
  usage: KeyUsage[];
}): Promise<CryptoKey> {
  const subtle = getSubtle();
  const combined = new Uint8Array(params.rootBits.byteLength + params.ephemeralBits.byteLength);
  combined.set(new Uint8Array(params.rootBits), 0);
  combined.set(new Uint8Array(params.ephemeralBits), params.rootBits.byteLength);

  const hkdfKey = await subtle.importKey('raw', combined, 'HKDF', false, ['deriveKey']);
  const info = new TextEncoder().encode(
    `eMesh-msg-v1|${params.conversationId}|${params.senderDeviceId}|epoch:${params.keyEpoch}|ctr:${params.ratchetCounter}`
  );
  const salt = new TextEncoder().encode(`eMesh-salt|${params.conversationId}`);

  return subtle.deriveKey(
    {
      name: 'HKDF',
      hash: 'SHA-256',
      salt,
      info,
    },
    hkdfKey,
    { name: 'AES-GCM', length: 256 },
    false,
    params.usage
  );
}

function buildEnvelopeSignatureInput(envelope: {
  messageId: string;
  conversationId: string;
  senderDeviceId: string;
  recipientDeviceId: string;
  ciphertext: string;
  iv: string;
  ephemeralPubKey: string;
  ratchetCounter: number;
  keyEpoch: number;
  messageType: MessageType;
  ephemeralTtlMs: EphemeralDurationMs;
  fileId?: string;
}): string {
  return [
    envelope.messageId,
    envelope.conversationId,
    envelope.senderDeviceId,
    envelope.recipientDeviceId,
    envelope.ciphertext,
    envelope.iv,
    envelope.ephemeralPubKey,
    String(envelope.ratchetCounter),
    String(envelope.keyEpoch),
    envelope.messageType,
    String(envelope.ephemeralTtlMs),
    envelope.fileId ?? '',
  ].join('|');
}

export async function encryptEnvelope(params: {
  sender: UnlockedIdentity;
  peer: PublicIdentity;
  conversationId: string;
  messageId?: string;
  messageType: MessageType;
  payload: DecryptedPayload;
  ephemeralTtlMs: EphemeralDurationMs;
  keyEpoch: number;
  ratchetCounter: number;
  fileId?: string;
}): Promise<EncryptedEnvelope> {
  const subtle = getSubtle();
  const messageId = params.messageId ?? generateId('msg');

  const ephemeralPair = await subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' },
    true,
    ['deriveBits']
  );
  const ephemeralPubJwk = await subtle.exportKey('jwk', ephemeralPair.publicKey);
  const ephemeralPubKey = canonicalPublicKeyString(ephemeralPubJwk);

  const peerIdentityPub = await subtle.importKey(
    'jwk',
    JSON.parse(params.peer.identityPublicKey) as JsonWebKey,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  const [rootBits, ephemeralBits] = await Promise.all([
    deriveConversationRootBits(params.sender.identityPrivateKey, params.peer.identityPublicKey),
    subtle.deriveBits({ name: 'ECDH', public: peerIdentityPub }, ephemeralPair.privateKey, 256),
  ]);

  const aesKey = await deriveMessageAesKey({
    rootBits,
    ephemeralBits,
    conversationId: params.conversationId,
    senderDeviceId: params.sender.deviceId,
    keyEpoch: params.keyEpoch,
    ratchetCounter: params.ratchetCounter,
    usage: ['encrypt'],
  });

  const iv = randomBytes(12);
  const aad = new TextEncoder().encode(
    `${params.conversationId}|${messageId}|${params.sender.deviceId}|${params.keyEpoch}|${params.ratchetCounter}`
  );
  const plaintext = new TextEncoder().encode(JSON.stringify(params.payload));
  const encrypted = new Uint8Array(
    await subtle.encrypt(
      { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer, additionalData: aad },
      aesKey,
      plaintext
    )
  );

  const ciphertext = bytesToBase64(encrypted);
  const ivB64 = bytesToBase64(iv);

  const sigInput = buildEnvelopeSignatureInput({
    messageId,
    conversationId: params.conversationId,
    senderDeviceId: params.sender.deviceId,
    recipientDeviceId: params.peer.deviceId,
    ciphertext,
    iv: ivB64,
    ephemeralPubKey,
    ratchetCounter: params.ratchetCounter,
    keyEpoch: params.keyEpoch,
    messageType: params.messageType,
    ephemeralTtlMs: params.ephemeralTtlMs,
    fileId: params.fileId,
  });

  const signature = await signWithDevice(params.sender.signingPrivateKey, sigInput);

  return {
    messageId,
    conversationId: params.conversationId,
    senderDeviceId: params.sender.deviceId,
    recipientDeviceId: params.peer.deviceId,
    ciphertext,
    iv: ivB64,
    ephemeralPubKey,
    ratchetCounter: params.ratchetCounter,
    keyEpoch: params.keyEpoch,
    signature,
    messageType: params.messageType,
    ephemeralTtlMs: params.ephemeralTtlMs,
    fileId: params.fileId,
    status: 'sent',
    createdAt: Date.now(),
  };
}

export async function decryptEnvelope(params: {
  receiver: UnlockedIdentity;
  peer: PublicIdentity;
  envelope: EncryptedEnvelope;
}): Promise<{ payload: DecryptedPayload; verifiedSignature: boolean }> {
  const subtle = getSubtle();
  const { envelope, receiver, peer } = params;

  const expectedSignerKey =
    envelope.senderDeviceId === receiver.deviceId
      ? canonicalPublicKeyString(receiver.signingPublicKey)
      : peer.signingPublicKey;

  const sigInput = buildEnvelopeSignatureInput(envelope);
  const verifiedSignature = await verifyDeviceSignature(expectedSignerKey, sigInput, envelope.signature);
  if (!verifiedSignature) {
    throw new Error('Signature cryptographique invalide : message potentiellement altéré.');
  }

  const ephemeralPubKey = await subtle.importKey(
    'jwk',
    JSON.parse(envelope.ephemeralPubKey) as JsonWebKey,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    []
  );

  const rootBits = await deriveConversationRootBits(
    receiver.identityPrivateKey,
    peer.identityPublicKey
  );

  // If the receiver is decrypting their own sent message from history, deriveBits uses receiver's private identity key + ephemeral pub?
  // Wait: sender encrypted with ECDH(ephemeralPriv, peerIdentityPub) -> receiver decrypts with ECDH(receiverIdentityPriv, ephemeralPub).
  // For sender's own sent messages stored locally, sender caches plaintext in encrypted local vault or we derive cleanly.
  const receiverIdentityPriv = await subtle.importKey(
    'jwk',
    receiver.identityPrivateKey,
    { name: 'ECDH', namedCurve: 'P-256' },
    false,
    ['deriveBits']
  );

  const ephemeralBits = await subtle.deriveBits(
    { name: 'ECDH', public: ephemeralPubKey },
    receiverIdentityPriv,
    256
  );

  const aesKey = await deriveMessageAesKey({
    rootBits,
    ephemeralBits,
    conversationId: envelope.conversationId,
    senderDeviceId: envelope.senderDeviceId,
    keyEpoch: envelope.keyEpoch,
    ratchetCounter: envelope.ratchetCounter,
    usage: ['decrypt'],
  });

  const aad = new TextEncoder().encode(
    `${envelope.conversationId}|${envelope.messageId}|${envelope.senderDeviceId}|${envelope.keyEpoch}|${envelope.ratchetCounter}`
  );
  const plaintext = await subtle.decrypt(
    {
      name: 'AES-GCM',
      iv: base64ToBytes(envelope.iv).buffer as ArrayBuffer,
      additionalData: aad,
    },
    aesKey,
    base64ToBytes(envelope.ciphertext).buffer as ArrayBuffer
  );

  return {
    payload: JSON.parse(new TextDecoder().decode(plaintext)) as DecryptedPayload,
    verifiedSignature,
  };
}

export async function encryptFileBytes(plainBytes: Uint8Array): Promise<{
  encryptedBytes: Uint8Array;
  fileKeyB64: string;
  fileIvB64: string;
}> {
  const subtle = getSubtle();
  const key = await subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, [
    'encrypt',
    'decrypt',
  ]);
  const iv = randomBytes(12);
  const encryptedBuffer = await subtle.encrypt(
    { name: 'AES-GCM', iv: iv.buffer as ArrayBuffer },
    key,
    plainBytes.buffer.slice(
      plainBytes.byteOffset,
      plainBytes.byteOffset + plainBytes.byteLength
    ) as ArrayBuffer
  );
  const rawKey = new Uint8Array(await subtle.exportKey('raw', key));
  return {
    encryptedBytes: new Uint8Array(encryptedBuffer),
    fileKeyB64: bytesToBase64(rawKey),
    fileIvB64: bytesToBase64(iv),
  };
}

export async function decryptFileBytes(
  encryptedBytes: Uint8Array,
  fileKeyB64: string,
  fileIvB64: string
): Promise<Uint8Array> {
  const subtle = getSubtle();
  const key = await subtle.importKey(
    'raw',
    base64ToBytes(fileKeyB64).buffer as ArrayBuffer,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt']
  );
  const plainBuffer = await subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBytes(fileIvB64).buffer as ArrayBuffer },
    key,
    encryptedBytes.buffer.slice(
      encryptedBytes.byteOffset,
      encryptedBytes.byteOffset + encryptedBytes.byteLength
    ) as ArrayBuffer
  );
  return new Uint8Array(plainBuffer);
}
