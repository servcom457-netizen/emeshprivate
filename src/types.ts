export type EphemeralDurationMs = 0 | 10000 | 30000 | 60000 | 300000 | 86400000;

export type MessageType = 'text' | 'audio' | 'image' | 'video' | 'document';

export type MessageStatus = 'sent' | 'delivered' | 'read' | 'expired';

export type AppScreen =
  | 'splash'
  | 'create-identity'
  | 'setup-pin'
  | 'unlock-pin'
  | 'home'
  | 'generate-code'
  | 'join-code'
  | 'scan-qr'
  | 'verify-identity'
  | 'chat'
  | 'settings'
  | 'associations'
  | 'delete-account';

export interface PublicIdentity {
  deviceId: string;
  pseudonym: string;
  identityPublicKey: string; // JWK JSON string (ECDH P-256 public)
  signingPublicKey: string; // JWK JSON string (ECDSA P-256 public)
  fingerprint: string;
}

export interface UnlockedIdentity {
  deviceId: string;
  pseudonym: string;
  identityPublicKey: JsonWebKey;
  identityPrivateKey: JsonWebKey;
  signingPublicKey: JsonWebKey;
  signingPrivateKey: JsonWebKey;
  fingerprint: string;
  createdAt: number;
}

export interface WrappedVaultRecord {
  deviceId: string;
  pseudonym: string;
  identityPublicKey: JsonWebKey;
  signingPublicKey: JsonWebKey;
  fingerprint: string;
  saltB64: string;
  ivB64: string;
  wrappedPrivateBundleB64: string;
  createdAt: number;
}

export interface PeerConversation {
  conversationId: string;
  peer: PublicIdentity;
  status: 'active' | 'revoked';
  ephemeralTtlMs: EphemeralDurationMs;
  keyEpoch: number;
  verifiedFingerprint?: string;
  createdAt: number;
  updatedAt: number;
  peerOnline?: boolean;
  lastActivityAt?: number;
}

export interface EncryptedEnvelope {
  messageId: string;
  conversationId: string;
  senderDeviceId: string;
  recipientDeviceId: string;
  ciphertext: string;
  iv: string;
  ephemeralPubKey: string;
  ratchetCounter: number;
  keyEpoch: number;
  signature: string;
  messageType: MessageType;
  ephemeralTtlMs: EphemeralDurationMs;
  fileId?: string;
  status: MessageStatus;
  createdAt: number;
  deliveredAt?: number;
  readAt?: number;
  expiresAt?: number;
}

export interface DecryptedMediaMeta {
  fileId: string;
  fileKeyB64: string;
  fileIvB64: string;
  mimeType: string;
  fileName: string;
  fileSize: number;
  durationMs?: number;
}

export interface DecryptedPayload {
  text?: string;
  media?: DecryptedMediaMeta;
  nonce: string;
  sentAt: number;
}

export interface DecryptedMessage {
  messageId: string;
  conversationId: string;
  senderDeviceId: string;
  recipientDeviceId: string;
  isMine: boolean;
  messageType: MessageType;
  payload: DecryptedPayload;
  status: MessageStatus;
  ephemeralTtlMs: EphemeralDurationMs;
  createdAt: number;
  readAt?: number;
  expiresAt?: number;
  verifiedSignature: boolean;
  keyEpoch: number;
  ratchetCounter: number;
  revealedInstant?: boolean;
  decryptionError?: string;
}

export const EPHEMERAL_OPTIONS: { label: string; shortLabel: string; value: EphemeralDurationMs }[] = [
  { label: 'Immédiatement après lecture', shortLabel: 'Immédiat', value: 0 },
  { label: '10 secondes', shortLabel: '10 s', value: 10000 },
  { label: '30 secondes', shortLabel: '30 s', value: 30000 },
  { label: '1 minute', shortLabel: '1 min', value: 60000 },
  { label: '5 minutes', shortLabel: '5 min', value: 300000 },
  { label: '24 heures', shortLabel: '24 h', value: 86400000 },
];
