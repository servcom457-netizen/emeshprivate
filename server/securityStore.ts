import crypto from 'node:crypto';

export interface ServerPublicIdentity {
  deviceId: string;
  pseudonym: string;
  identityPublicKey: string;
  signingPublicKey: string;
  fingerprint: string;
  revoked: boolean;
  createdAt: number;
}

export interface PairingCodeRecord {
  codeHash: string;
  creatorDeviceId: string;
  expiresAt: number;
  used: boolean;
  failedAttempts: number;
}

export type EphemeralTtl = 0 | 10000 | 30000 | 60000 | 300000 | 86400000;

export interface ServerConversation {
  conversationId: string;
  participants: [string, string];
  status: 'active' | 'revoked';
  ephemeralTtlMs: EphemeralTtl;
  keyEpoch: number;
  createdAt: number;
  updatedAt: number;
}

export interface ServerEncryptedMessage {
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
  messageType: 'text' | 'audio' | 'image' | 'video' | 'document';
  ephemeralTtlMs: EphemeralTtl;
  fileId?: string;
  status: 'sent' | 'delivered' | 'read' | 'expired';
  createdAt: number;
  deliveredAt?: number;
  readAt?: number;
  expiresAt?: number;
}

export interface EncryptedFileRecord {
  fileId: string;
  conversationId: string;
  uploaderDeviceId: string;
  byteLength: number;
  createdAt: number;
  expiresAt: number;
}

interface SessionRecord {
  tokenId: string;
  deviceId: string;
  expiresAt: number;
}

interface AuthChallengeRecord {
  challengeId: string;
  deviceId: string;
  nonce: string;
  expiresAt: number;
}

const PAIRING_ALPHABET = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
const PAIRING_CODE_LENGTH = 10; // Formatted XXXXX-XXXXX (10 chars >= 8 chars requirement)
const PAIRING_TTL_MS = 10 * 60 * 1000;
const SESSION_TTL_MS = 24 * 60 * 60 * 1000;
const CHALLENGE_TTL_MS = 60 * 1000;
const MAX_REDEEM_ATTEMPTS_PER_WINDOW = 5;
const RATE_LIMIT_WINDOW_MS = 10 * 60 * 1000;
const VALID_ID_RE = /^[a-zA-Z0-9_-]{4,128}$/;

export function normalizePairingCode(raw: string): string {
  return raw.toUpperCase().replace(/[^A-Z0-9]/g, '');
}

export function formatPairingCode(raw: string): string {
  const clean = normalizePairingCode(raw);
  if (clean.length <= 5) return clean;
  return `${clean.slice(0, 5)}-${clean.slice(5)}`;
}

export class EmeshSecurityStore {
  private readonly devices = new Map<string, ServerPublicIdentity>();
  private readonly challenges = new Map<string, AuthChallengeRecord>();
  private readonly sessions = new Map<string, SessionRecord>();
  private readonly pairingCodes = new Map<string, PairingCodeRecord>();
  private readonly conversations = new Map<string, ServerConversation>();
  private readonly messagesByConversation = new Map<string, Map<string, ServerEncryptedMessage>>();
  private readonly seenMessageNonces = new Set<string>();
  private readonly files = new Map<string, EncryptedFileRecord>();
  private readonly redeemAttemptsByActor = new Map<string, number[]>();
  private readonly sessionSecret: Buffer;

  constructor(sessionSecretHex?: string) {
    this.sessionSecret = sessionSecretHex
      ? Buffer.from(sessionSecretHex, 'hex')
      : crypto.randomBytes(32);
  }

  private hashCode(normalizedCode: string): string {
    return crypto.createHash('sha256').update(`eMesh-pair:${normalizedCode}`).digest('hex');
  }

  private signSessionToken(tokenId: string, deviceId: string, expiresAt: number): string {
    const payload = `${tokenId}.${deviceId}.${expiresAt}`;
    const mac = crypto.createHmac('sha256', this.sessionSecret).update(payload).digest('base64url');
    return `${payload}.${mac}`;
  }

  verifySessionToken(token: string, nowMs = Date.now()): SessionRecord | null {
    if (!token || typeof token !== 'string') return null;
    const parts = token.split('.');
    if (parts.length !== 4) return null;
    const [tokenId, deviceId, expiresAtStr, mac] = parts;
    const expiresAt = Number(expiresAtStr);
    if (!Number.isFinite(expiresAt) || nowMs > expiresAt) return null;

    const payload = `${tokenId}.${deviceId}.${expiresAt}`;
    const expectedMac = crypto
      .createHmac('sha256', this.sessionSecret)
      .update(payload)
      .digest('base64url');

    const macBuf = Buffer.from(mac);
    const expBuf = Buffer.from(expectedMac);
    if (macBuf.length !== expBuf.length || !crypto.timingSafeEqual(macBuf, expBuf)) {
      return null;
    }

    const session = this.sessions.get(tokenId);
    if (!session || session.deviceId !== deviceId || nowMs > session.expiresAt) {
      return null;
    }

    const device = this.devices.get(deviceId);
    if (!device || device.revoked) {
      return null;
    }

    return session;
  }

  async registerDevice(input: {
    deviceId: string;
    pseudonym: string;
    identityPublicKey: string;
    signingPublicKey: string;
    fingerprint: string;
    nowMs?: number;
  }): Promise<ServerPublicIdentity> {
    const nowMs = input.nowMs ?? Date.now();
    if (!VALID_ID_RE.test(input.deviceId)) {
      throw new Error('Identifiant d’appareil invalide.');
    }
    const cleanPseudo = input.pseudonym.trim();
    if (cleanPseudo.length < 2 || cleanPseudo.length > 40) {
      throw new Error('Le pseudonyme doit contenir entre 2 et 40 caractères.');
    }

    let idPub: JsonWebKey;
    let sigPub: JsonWebKey;
    try {
      idPub = JSON.parse(input.identityPublicKey) as JsonWebKey;
      sigPub = JSON.parse(input.signingPublicKey) as JsonWebKey;
    } catch {
      throw new Error('Clés publiques JWK invalides.');
    }

    if (idPub.kty !== 'EC' || idPub.crv !== 'P-256' || sigPub.kty !== 'EC' || sigPub.crv !== 'P-256') {
      throw new Error('Courbe cryptographique non supportée (P-256 requise).');
    }

    // Verify fingerprint server-side to prevent spoofed fingerprints
    const canonical = `eMesh-fp-v1|${JSON.stringify({
      crv: idPub.crv,
      kty: idPub.kty,
      x: idPub.x,
      y: idPub.y,
    })}|${JSON.stringify({
      crv: sigPub.crv,
      kty: sigPub.kty,
      x: sigPub.x,
      y: sigPub.y,
    })}`;
    const hashHex = crypto.createHash('sha256').update(canonical).digest('hex').toUpperCase();
    const groups: string[] = [];
    for (let i = 0; i < 48; i += 4) {
      groups.push(hashHex.slice(i, i + 4));
    }
    const expectedFingerprint = groups.join(' ');
    if (expectedFingerprint !== input.fingerprint) {
      throw new Error('Empreinte cryptographique incohérente.');
    }

    const existing = this.devices.get(input.deviceId);
    if (existing) {
      if (
        existing.identityPublicKey !== input.identityPublicKey ||
        existing.signingPublicKey !== input.signingPublicKey
      ) {
        throw new Error('Conflit d’identité : cet identifiant possède déjà des clés différentes.');
      }
      existing.pseudonym = cleanPseudo;
      return existing;
    }

    const record: ServerPublicIdentity = {
      deviceId: input.deviceId,
      pseudonym: cleanPseudo,
      identityPublicKey: input.identityPublicKey,
      signingPublicKey: input.signingPublicKey,
      fingerprint: input.fingerprint,
      revoked: false,
      createdAt: nowMs,
    };
    this.devices.set(input.deviceId, record);
    return record;
  }

  updatePseudonym(deviceId: string, pseudonym: string): ServerPublicIdentity {
    const device = this.devices.get(deviceId);
    if (!device || device.revoked) {
      throw new Error('Appareil introuvable ou révoqué.');
    }
    const clean = pseudonym.trim();
    if (clean.length < 2 || clean.length > 40) {
      throw new Error('Le pseudonyme doit contenir entre 2 et 40 caractères.');
    }
    device.pseudonym = clean;
    return device;
  }

  getDevice(deviceId: string): ServerPublicIdentity | undefined {
    return this.devices.get(deviceId);
  }

  issueAuthChallenge(deviceId: string, nowMs = Date.now()): { challengeId: string; nonce: string } {
    const device = this.devices.get(deviceId);
    if (!device || device.revoked) {
      throw new Error('Appareil inconnu ou révoqué.');
    }
    const challengeId = `chl_${crypto.randomBytes(12).toString('hex')}`;
    const nonce = crypto.randomBytes(32).toString('base64url');
    this.challenges.set(challengeId, {
      challengeId,
      deviceId,
      nonce,
      expiresAt: nowMs + CHALLENGE_TTL_MS,
    });
    return { challengeId, nonce };
  }

  async verifyAuthChallenge(
    deviceId: string,
    challengeId: string,
    signatureB64: string,
    nowMs = Date.now()
  ): Promise<{ token: string; expiresAt: number }> {
    const challenge = this.challenges.get(challengeId);
    this.challenges.delete(challengeId);
    if (!challenge || challenge.deviceId !== deviceId || nowMs > challenge.expiresAt) {
      throw new Error('Défi d’authentification invalide ou expiré.');
    }

    const device = this.devices.get(deviceId);
    if (!device || device.revoked) {
      throw new Error('Appareil inconnu ou révoqué.');
    }

    const pubJwk = JSON.parse(device.signingPublicKey) as JsonWebKey;
    const cryptoKey = await globalThis.crypto.subtle.importKey(
      'jwk',
      pubJwk,
      { name: 'ECDSA', namedCurve: 'P-256' },
      false,
      ['verify']
    );
    const sigBytes = Buffer.from(signatureB64, 'base64');
    const payload = new TextEncoder().encode(`eMesh-auth:${deviceId}:${challenge.nonce}`);
    const ok = await globalThis.crypto.subtle.verify(
      { name: 'ECDSA', hash: 'SHA-256' },
      cryptoKey,
      sigBytes,
      payload
    );
    if (!ok) {
      throw new Error('Signature cryptographique d’authentification refusée.');
    }

    const tokenId = `ses_${crypto.randomBytes(16).toString('hex')}`;
    const expiresAt = nowMs + SESSION_TTL_MS;
    this.sessions.set(tokenId, { tokenId, deviceId, expiresAt });
    return {
      token: this.signSessionToken(tokenId, deviceId, expiresAt),
      expiresAt,
    };
  }

  logoutSession(token: string): void {
    const parts = token.split('.');
    if (parts.length === 4) {
      this.sessions.delete(parts[0]);
    }
  }

  createPairingCode(creatorDeviceId: string, nowMs = Date.now()): { code: string; expiresAt: number } {
    const device = this.devices.get(creatorDeviceId);
    if (!device || device.revoked) {
      throw new Error('Appareil non autorisé.');
    }

    // Invalidate any previous unused pairing codes issued by this creator
    for (const [hash, rec] of this.pairingCodes.entries()) {
      if (rec.creatorDeviceId === creatorDeviceId && !rec.used) {
        this.pairingCodes.delete(hash);
      }
    }

    const randomBuf = crypto.randomBytes(PAIRING_CODE_LENGTH);
    let rawCode = '';
    for (let i = 0; i < PAIRING_CODE_LENGTH; i++) {
      rawCode += PAIRING_ALPHABET[randomBuf[i] % PAIRING_ALPHABET.length];
    }

    const codeHash = this.hashCode(rawCode);
    const expiresAt = nowMs + PAIRING_TTL_MS;
    this.pairingCodes.set(codeHash, {
      codeHash,
      creatorDeviceId,
      expiresAt,
      used: false,
      failedAttempts: 0,
    });

    return {
      code: formatPairingCode(rawCode),
      expiresAt,
    };
  }

  private checkAndRecordRedeemRateLimit(actorKey: string, nowMs: number): void {
    const attempts = (this.redeemAttemptsByActor.get(actorKey) ?? []).filter(
      (ts) => nowMs - ts < RATE_LIMIT_WINDOW_MS
    );
    if (attempts.length >= MAX_REDEEM_ATTEMPTS_PER_WINDOW) {
      throw new Error(
        'Trop de tentatives d’association. Patientez quelques minutes avant de réessayer.'
      );
    }
    attempts.push(nowMs);
    this.redeemAttemptsByActor.set(actorKey, attempts);
  }

  redeemPairingCode(
    redeemerDeviceId: string,
    rawCode: string,
    actorKey = redeemerDeviceId,
    nowMs = Date.now()
  ): {
    conversation: ServerConversation;
    creator: ServerPublicIdentity;
    redeemer: ServerPublicIdentity;
  } {
    const redeemer = this.devices.get(redeemerDeviceId);
    if (!redeemer || redeemer.revoked) {
      throw new Error('Appareil non autorisé.');
    }

    this.checkAndRecordRedeemRateLimit(actorKey, nowMs);

    const normalized = normalizePairingCode(rawCode);
    if (normalized.length < 8) {
      throw new Error('Code invalide : au moins 8 caractères requis.');
    }

    const codeHash = this.hashCode(normalized);
    const record = this.pairingCodes.get(codeHash);

    if (!record) {
      throw new Error('Code de connexion introuvable ou déjà invalidé.');
    }
    if (record.used) {
      throw new Error('Ce code unique a déjà été utilisé.');
    }
    if (nowMs > record.expiresAt) {
      this.pairingCodes.delete(codeHash);
      throw new Error('Ce code de connexion a expiré (validité maximale de 10 minutes).');
    }
    if (record.creatorDeviceId === redeemerDeviceId) {
      throw new Error('Impossible de s’associer avec le même appareil.');
    }

    const creator = this.devices.get(record.creatorDeviceId);
    if (!creator || creator.revoked) {
      this.pairingCodes.delete(codeHash);
      throw new Error('Le correspondant à l’origine du code n’est plus actif.');
    }

    // Single-use atomic invalidation
    record.used = true;
    this.pairingCodes.delete(codeHash);
    // Clear rate-limit history on success
    this.redeemAttemptsByActor.delete(actorKey);

    const conversationId = `conv_${crypto.randomBytes(12).toString('hex')}`;
    const conversation: ServerConversation = {
      conversationId,
      participants: [creator.deviceId, redeemer.deviceId],
      status: 'active',
      ephemeralTtlMs: 30000,
      keyEpoch: 1,
      createdAt: nowMs,
      updatedAt: nowMs,
    };
    this.conversations.set(conversationId, conversation);
    this.messagesByConversation.set(conversationId, new Map());

    return { conversation, creator, redeemer };
  }

  assertConversationMember(conversationId: string, deviceId: string): ServerConversation {
    const conv = this.conversations.get(conversationId);
    if (!conv) {
      throw new Error('Conversation introuvable.');
    }
    if (!conv.participants.includes(deviceId)) {
      throw new Error('Accès refusé : vous ne faites pas partie de cette association.');
    }
    return conv;
  }

  listConversationsForDevice(deviceId: string): Array<{
    conversation: ServerConversation;
    peer: ServerPublicIdentity;
  }> {
    const result: Array<{ conversation: ServerConversation; peer: ServerPublicIdentity }> = [];
    for (const conv of this.conversations.values()) {
      if (conv.participants.includes(deviceId)) {
        const peerId = conv.participants[0] === deviceId ? conv.participants[1] : conv.participants[0];
        const peer = this.devices.get(peerId);
        if (peer) {
          result.push({ conversation: conv, peer });
        }
      }
    }
    return result.sort((a, b) => b.conversation.updatedAt - a.conversation.updatedAt);
  }

  updateConversationSettings(
    conversationId: string,
    deviceId: string,
    patch: { ephemeralTtlMs?: number; rotateKeyEpoch?: boolean },
    nowMs = Date.now()
  ): ServerConversation {
    const conv = this.assertConversationMember(conversationId, deviceId);
    if (conv.status !== 'active') {
      throw new Error('Cette association a été révoquée.');
    }
    if (typeof patch.ephemeralTtlMs === 'number') {
      const allowed = [0, 10000, 30000, 60000, 300000, 86400000];
      if (!allowed.includes(patch.ephemeralTtlMs)) {
        throw new Error('Durée éphémère non supportée.');
      }
      conv.ephemeralTtlMs = patch.ephemeralTtlMs as EphemeralTtl;
    }
    if (patch.rotateKeyEpoch) {
      conv.keyEpoch += 1;
    }
    conv.updatedAt = nowMs;
    return conv;
  }

  revokeConversation(conversationId: string, deviceId: string, nowMs = Date.now()): {
    conversation: ServerConversation;
    deletedFileIds: string[];
  } {
    const conv = this.assertConversationMember(conversationId, deviceId);
    conv.status = 'revoked';
    conv.updatedAt = nowMs;

    const msgs = this.messagesByConversation.get(conversationId);
    const deletedFileIds: string[] = [];
    if (msgs) {
      for (const msg of msgs.values()) {
        if (msg.fileId) deletedFileIds.push(msg.fileId);
      }
      msgs.clear();
    }
    for (const [fileId, fileRec] of this.files.entries()) {
      if (fileRec.conversationId === conversationId) {
        this.files.delete(fileId);
        deletedFileIds.push(fileId);
      }
    }
    return { conversation: conv, deletedFileIds: Array.from(new Set(deletedFileIds)) };
  }

  revokeIdentity(deviceId: string, nowMs = Date.now()): {
    revokedConversationIds: string[];
    deletedFileIds: string[];
  } {
    const device = this.devices.get(deviceId);
    if (device) {
      device.revoked = true;
    }
    for (const [sid, session] of this.sessions.entries()) {
      if (session.deviceId === deviceId) {
        this.sessions.delete(sid);
      }
    }
    const revokedConversationIds: string[] = [];
    const deletedFileIds: string[] = [];
    for (const conv of this.conversations.values()) {
      if (conv.participants.includes(deviceId) && conv.status === 'active') {
        const res = this.revokeConversation(conv.conversationId, deviceId, nowMs);
        revokedConversationIds.push(conv.conversationId);
        deletedFileIds.push(...res.deletedFileIds);
      }
    }
    return { revokedConversationIds, deletedFileIds };
  }

  storeEncryptedMessage(
    senderDeviceId: string,
    envelope: Omit<ServerEncryptedMessage, 'status' | 'createdAt'>,
    nowMs = Date.now()
  ): ServerEncryptedMessage {
    if (envelope.senderDeviceId !== senderDeviceId) {
      throw new Error('Usurpation d’identifiant expéditeur bloquée.');
    }
    const conv = this.assertConversationMember(envelope.conversationId, senderDeviceId);
    if (conv.status !== 'active') {
      throw new Error('Impossible d’envoyer : l’association a été révoquée.');
    }
    const expectedRecipient =
      conv.participants[0] === senderDeviceId ? conv.participants[1] : conv.participants[0];
    if (envelope.recipientDeviceId !== expectedRecipient) {
      throw new Error('Destinataire invalide pour cette conversation privée.');
    }

    // Anti-replay check
    const replayKey = `${envelope.conversationId}:${senderDeviceId}:${envelope.messageId}`;
    if (this.seenMessageNonces.has(replayKey)) {
      throw new Error('Enveloppe dupliquée détectée (protection anti-rejeu).');
    }
    this.seenMessageNonces.add(replayKey);

    const stored: ServerEncryptedMessage = {
      ...envelope,
      status: 'sent',
      createdAt: nowMs,
    };

    let msgMap = this.messagesByConversation.get(envelope.conversationId);
    if (!msgMap) {
      msgMap = new Map();
      this.messagesByConversation.set(envelope.conversationId, msgMap);
    }
    msgMap.set(stored.messageId, stored);
    conv.updatedAt = nowMs;
    return stored;
  }

  getMessagesForConversation(conversationId: string, deviceId: string): ServerEncryptedMessage[] {
    this.assertConversationMember(conversationId, deviceId);
    const msgMap = this.messagesByConversation.get(conversationId);
    if (!msgMap) return [];
    return Array.from(msgMap.values())
      .filter((m) => m.status !== 'expired')
      .sort((a, b) => a.createdAt - b.createdAt);
  }

  markMessageDelivered(
    conversationId: string,
    messageId: string,
    deviceId: string,
    nowMs = Date.now()
  ): ServerEncryptedMessage | null {
    this.assertConversationMember(conversationId, deviceId);
    const msg = this.messagesByConversation.get(conversationId)?.get(messageId);
    if (!msg || msg.recipientDeviceId !== deviceId) return null;
    if (msg.status === 'sent') {
      msg.status = 'delivered';
      msg.deliveredAt = nowMs;
    }
    return msg;
  }

  markMessageRead(
    conversationId: string,
    messageId: string,
    readerDeviceId: string,
    nowMs = Date.now()
  ): { message: ServerEncryptedMessage; expiredImmediately: boolean } | null {
    this.assertConversationMember(conversationId, readerDeviceId);
    const msgMap = this.messagesByConversation.get(conversationId);
    const msg = msgMap?.get(messageId);
    if (!msg || msg.recipientDeviceId !== readerDeviceId || msg.status === 'expired') {
      return null;
    }
    if (!msg.readAt) {
      msg.readAt = nowMs;
      msg.expiresAt = nowMs + msg.ephemeralTtlMs;
    }
    msg.status = 'read';

    if (msg.ephemeralTtlMs === 0) {
      msg.status = 'expired';
      msgMap?.delete(messageId);
      if (msg.fileId) {
        this.files.delete(msg.fileId);
      }
      return { message: msg, expiredImmediately: true };
    }
    return { message: msg, expiredImmediately: false };
  }

  registerEncryptedFile(params: {
    fileId: string;
    conversationId: string;
    uploaderDeviceId: string;
    byteLength: number;
    nowMs?: number;
  }): EncryptedFileRecord {
    const nowMs = params.nowMs ?? Date.now();
    const conv = this.assertConversationMember(params.conversationId, params.uploaderDeviceId);
    if (conv.status !== 'active') {
      throw new Error('Association révoquée.');
    }
    const record: EncryptedFileRecord = {
      fileId: params.fileId,
      conversationId: params.conversationId,
      uploaderDeviceId: params.uploaderDeviceId,
      byteLength: params.byteLength,
      createdAt: nowMs,
      expiresAt: nowMs + 24 * 60 * 60 * 1000,
    };
    this.files.set(params.fileId, record);
    return record;
  }

  getEncryptedFile(fileId: string, requesterDeviceId: string): EncryptedFileRecord {
    const file = this.files.get(fileId);
    if (!file) {
      throw new Error('Fichier chiffré introuvable ou expiré.');
    }
    this.assertConversationMember(file.conversationId, requesterDeviceId);
    return file;
  }

  sweepExpired(nowMs = Date.now()): {
    expiredMessages: Array<{
      conversationId: string;
      messageId: string;
      senderDeviceId: string;
      recipientDeviceId: string;
    }>;
    expiredFileIds: string[];
  } {
    const expiredMessages: Array<{
      conversationId: string;
      messageId: string;
      senderDeviceId: string;
      recipientDeviceId: string;
    }> = [];
    const expiredFileIds: string[] = [];

    for (const [hash, code] of this.pairingCodes.entries()) {
      if (nowMs > code.expiresAt || code.used) {
        this.pairingCodes.delete(hash);
      }
    }

    for (const [convId, msgMap] of this.messagesByConversation.entries()) {
      for (const [msgId, msg] of msgMap.entries()) {
        if (typeof msg.expiresAt === 'number' && nowMs >= msg.expiresAt) {
          msg.status = 'expired';
          msgMap.delete(msgId);
          expiredMessages.push({
            conversationId: convId,
            messageId: msgId,
            senderDeviceId: msg.senderDeviceId,
            recipientDeviceId: msg.recipientDeviceId,
          });
          if (msg.fileId) {
            this.files.delete(msg.fileId);
            expiredFileIds.push(msg.fileId);
          }
        }
      }
    }

    for (const [fileId, file] of this.files.entries()) {
      if (nowMs >= file.expiresAt) {
        this.files.delete(fileId);
        expiredFileIds.push(fileId);
      }
    }

    return { expiredMessages, expiredFileIds };
  }
}
