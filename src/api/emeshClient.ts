import { signWithDevice, toPublicIdentity } from '../crypto/emeshCrypto';
import type {
  EncryptedEnvelope,
  EphemeralDurationMs,
  PeerConversation,
  UnlockedIdentity,
} from '../types';

export interface AuthSession {
  token: string;
  expiresAt: number;
}

async function jsonRequest<T>(
  path: string,
  options: RequestInit = {},
  token?: string
): Promise<T> {
  const headers = new Headers(options.headers);
  if (!(options.body instanceof Uint8Array)) {
    headers.set('Content-Type', 'application/json');
  }
  if (token) {
    headers.set('Authorization', `Bearer ${token}`);
  }
  const res = await fetch(path, { ...options, headers });
  if (!res.ok) {
    let message = `Erreur réseau (${res.status})`;
    try {
      const data = (await res.json()) as { error?: string };
      if (data.error) message = data.error;
    } catch {
      // keep default
    }
    throw new Error(message);
  }
  return (await res.json()) as T;
}

export async function authenticateDeviceSession(identity: UnlockedIdentity): Promise<AuthSession> {
  const pub = toPublicIdentity(identity);
  await jsonRequest('/api/identity/register', {
    method: 'POST',
    body: JSON.stringify(pub),
  });

  const challenge = await jsonRequest<{ challengeId: string; nonce: string }>(
    '/api/auth/challenge',
    {
      method: 'POST',
      body: JSON.stringify({ deviceId: identity.deviceId }),
    }
  );

  const signature = await signWithDevice(
    identity.signingPrivateKey,
    `eMesh-auth:${identity.deviceId}:${challenge.nonce}`
  );

  return jsonRequest<AuthSession>('/api/auth/verify', {
    method: 'POST',
    body: JSON.stringify({
      deviceId: identity.deviceId,
      challengeId: challenge.challengeId,
      signature,
    }),
  });
}

export async function logoutDeviceSession(token: string): Promise<void> {
  await jsonRequest('/api/auth/logout', { method: 'POST' }, token);
}

export async function updateServerPseudonym(token: string, pseudonym: string): Promise<void> {
  await jsonRequest(
    '/api/identity/pseudonym',
    { method: 'PATCH', body: JSON.stringify({ pseudonym }) },
    token
  );
}

export async function revokeServerIdentity(token: string): Promise<void> {
  await jsonRequest('/api/identity/revoke', { method: 'POST' }, token);
}

export async function createPairingCodeApi(
  token: string
): Promise<{ code: string; expiresAt: number }> {
  return jsonRequest('/api/pairing/create', { method: 'POST' }, token);
}

export async function redeemPairingCodeApi(
  token: string,
  code: string
): Promise<{ conversation: PeerConversation }> {
  return jsonRequest(
    '/api/pairing/redeem',
    { method: 'POST', body: JSON.stringify({ code }) },
    token
  );
}

export async function fetchConversationsApi(
  token: string
): Promise<{ conversations: PeerConversation[] }> {
  return jsonRequest('/api/conversations', { method: 'GET' }, token);
}

export async function updateConversationSettingsApi(
  token: string,
  conversationId: string,
  patch: { ephemeralTtlMs?: EphemeralDurationMs; rotateKeyEpoch?: boolean }
): Promise<{ conversation: PeerConversation }> {
  return jsonRequest(
    `/api/conversations/${encodeURIComponent(conversationId)}/settings`,
    { method: 'PATCH', body: JSON.stringify(patch) },
    token
  );
}

export async function revokeConversationApi(
  token: string,
  conversationId: string
): Promise<void> {
  await jsonRequest(
    `/api/conversations/${encodeURIComponent(conversationId)}/revoke`,
    { method: 'POST' },
    token
  );
}

export async function fetchMessagesApi(
  token: string,
  conversationId: string
): Promise<{ messages: EncryptedEnvelope[] }> {
  return jsonRequest(
    `/api/conversations/${encodeURIComponent(conversationId)}/messages`,
    { method: 'GET' },
    token
  );
}

export async function sendEncryptedMessageApi(
  token: string,
  envelope: EncryptedEnvelope
): Promise<{ message: EncryptedEnvelope }> {
  return jsonRequest(
    '/api/messages',
    { method: 'POST', body: JSON.stringify(envelope) },
    token
  );
}

export async function markMessageReadApi(
  token: string,
  conversationId: string,
  messageId: string
): Promise<{ message: EncryptedEnvelope; expiredImmediately: boolean }> {
  return jsonRequest(
    `/api/conversations/${encodeURIComponent(conversationId)}/messages/${encodeURIComponent(messageId)}/read`,
    { method: 'POST' },
    token
  );
}

export async function uploadEncryptedBlobApi(
  token: string,
  conversationId: string,
  encryptedBytes: Uint8Array
): Promise<{ fileId: string; byteLength: number }> {
  const res = await fetch(`/api/files/${encodeURIComponent(conversationId)}`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/octet-stream',
    },
    body: encryptedBytes.buffer.slice(
      encryptedBytes.byteOffset,
      encryptedBytes.byteOffset + encryptedBytes.byteLength
    ) as ArrayBuffer,
  });
  if (!res.ok) {
    let message = 'Échec de l’envoi du fichier chiffré.';
    try {
      const data = (await res.json()) as { error?: string };
      if (data.error) message = data.error;
    } catch {
      // ignore
    }
    throw new Error(message);
  }
  return (await res.json()) as { fileId: string; byteLength: number };
}

export async function downloadEncryptedBlobApi(
  token: string,
  fileId: string
): Promise<Uint8Array> {
  const res = await fetch(`/api/files/${encodeURIComponent(fileId)}`, {
    method: 'GET',
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) {
    throw new Error('Fichier chiffré expiré ou inaccessible.');
  }
  return new Uint8Array(await res.arrayBuffer());
}

export type WsServerEvent =
  | { type: 'presence:update'; conversationId: string; deviceId: string; online: boolean }
  | { type: 'pairing:completed'; conversation: PeerConversation }
  | { type: 'msg:new'; envelope: EncryptedEnvelope }
  | { type: 'msg:delivered'; conversationId: string; messageId: string; deliveredAt: number }
  | { type: 'msg:read'; conversationId: string; messageId: string; readAt: number; expiresAt: number }
  | { type: 'msg:expired'; conversationId: string; messageId: string }
  | {
      type: 'conversation:updated';
      conversationId: string;
      ephemeralTtlMs: EphemeralDurationMs;
      keyEpoch: number;
      updatedAt: number;
    }
  | { type: 'conversation:revoked'; conversationId: string; revokedBy: string };
