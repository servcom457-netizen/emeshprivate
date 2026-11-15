import express from 'express';
import http from 'node:http';
import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';
import { WebSocketServer, WebSocket } from 'ws';
import { EmeshSecurityStore } from './server/securityStore.ts';
import type { ServerEncryptedMessage } from './server/securityStore.ts';

const PORT = Number(process.env.PORT || 3000);
const BLOB_DIR = path.resolve(process.cwd(), '.emesh-blobs');
const SAFE_ID_RE = /^[a-zA-Z0-9_-]{4,128}$/;

async function ensureBlobDir() {
  await fs.mkdir(BLOB_DIR, { recursive: true });
}

async function unlinkBlobSafe(fileId: string) {
  if (!SAFE_ID_RE.test(fileId)) return;
  try {
    await fs.unlink(path.join(BLOB_DIR, `${fileId}.enc`));
  } catch {
    // Ignore if already removed
  }
}

async function startServer() {
  await ensureBlobDir();

  const store = new EmeshSecurityStore(process.env.EMESH_SESSION_SECRET);
  const app = express();
  app.disable('x-powered-by');

  app.use((_req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    next();
  });

  app.use(express.json({ limit: '512kb' }));

  const server = http.createServer(app);
  const wss = new WebSocketServer({ server, path: '/ws' });
  const deviceSockets = new Map<string, Set<WebSocket>>();

  function isDeviceOnline(deviceId: string): boolean {
    const sockets = deviceSockets.get(deviceId);
    if (!sockets || sockets.size === 0) return false;
    for (const sock of sockets) {
      if (sock.readyState === WebSocket.OPEN) return true;
    }
    return false;
  }

  function sendToDevice(deviceId: string, event: Record<string, unknown>) {
    const sockets = deviceSockets.get(deviceId);
    if (!sockets) return;
    const payload = JSON.stringify(event);
    for (const sock of sockets) {
      if (sock.readyState === WebSocket.OPEN) {
        sock.send(payload);
      }
    }
  }

  function broadcastPresence(deviceId: string, online: boolean) {
    const convs = store.listConversationsForDevice(deviceId);
    for (const { conversation, peer } of convs) {
      if (conversation.status === 'active') {
        sendToDevice(peer.deviceId, {
          type: 'presence:update',
          conversationId: conversation.conversationId,
          deviceId,
          online,
        });
      }
    }
  }

  function authenticateRequest(
    req: express.Request,
    res: express.Response
  ): { deviceId: string; token: string } | null {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';
    const session = store.verifySessionToken(token);
    if (!session) {
      res.status(401).json({ error: 'Session expirée ou non autorisée.' });
      return null;
    }
    return { deviceId: session.deviceId, token };
  }

  // Health endpoint
  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, service: 'emesh-relay', timestamp: Date.now() });
  });

  // 1. Register device public keys (never private keys or PINs)
  app.post('/api/identity/register', async (req, res) => {
    try {
      const { deviceId, pseudonym, identityPublicKey, signingPublicKey, fingerprint } = req.body ?? {};
      const record = await store.registerDevice({
        deviceId,
        pseudonym,
        identityPublicKey,
        signingPublicKey,
        fingerprint,
      });
      res.json({ device: record });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Erreur d’enregistrement.' });
    }
  });

  // 2. Challenge-response authentication (ECDSA signature verification)
  app.post('/api/auth/challenge', (req, res) => {
    try {
      const { deviceId } = req.body ?? {};
      const challenge = store.issueAuthChallenge(deviceId);
      res.json(challenge);
    } catch (err) {
      res.status(404).json({ error: err instanceof Error ? err.message : 'Appareil introuvable.' });
    }
  });

  app.post('/api/auth/verify', async (req, res) => {
    try {
      const { deviceId, challengeId, signature } = req.body ?? {};
      const session = await store.verifyAuthChallenge(deviceId, challengeId, signature);
      res.json(session);
    } catch (err) {
      res.status(401).json({ error: err instanceof Error ? err.message : 'Authentification refusée.' });
    }
  });

  app.post('/api/auth/logout', (req, res) => {
    const auth = authenticateRequest(req, res);
    if (!auth) return;
    store.logoutSession(auth.token);
    res.json({ ok: true });
  });

  // Update pseudonym
  app.patch('/api/identity/pseudonym', (req, res) => {
    const auth = authenticateRequest(req, res);
    if (!auth) return;
    try {
      const { pseudonym } = req.body ?? {};
      const updated = store.updatePseudonym(auth.deviceId, String(pseudonym ?? ''));
      res.json({ device: updated });
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Erreur.' });
    }
  });

  // Revoke identity & all associations
  app.post('/api/identity/revoke', async (req, res) => {
    const auth = authenticateRequest(req, res);
    if (!auth) return;
    const convs = store.listConversationsForDevice(auth.deviceId);
    const { revokedConversationIds, deletedFileIds } = store.revokeIdentity(auth.deviceId);

    for (const fileId of deletedFileIds) {
      await unlinkBlobSafe(fileId);
    }
    for (const { conversation, peer } of convs) {
      if (revokedConversationIds.includes(conversation.conversationId)) {
        sendToDevice(peer.deviceId, {
          type: 'conversation:revoked',
          conversationId: conversation.conversationId,
          revokedBy: auth.deviceId,
        });
      }
    }
    const sockets = deviceSockets.get(auth.deviceId);
    if (sockets) {
      for (const sock of sockets) sock.close(4001, 'Identity revoked');
    }
    res.json({ ok: true, revokedConversationIds });
  });

  // 3. Single-use pairing code creation & redemption
  app.post('/api/pairing/create', (req, res) => {
    const auth = authenticateRequest(req, res);
    if (!auth) return;
    try {
      const result = store.createPairingCode(auth.deviceId);
      res.json(result);
    } catch (err) {
      res.status(400).json({ error: err instanceof Error ? err.message : 'Impossible de créer le code.' });
    }
  });

  app.post('/api/pairing/redeem', (req, res) => {
    const auth = authenticateRequest(req, res);
    if (!auth) return;
    try {
      const { code } = req.body ?? {};
      const actorIp = req.ip || 'unknown';
      const actorKey = `${auth.deviceId}:${actorIp}`;
      const paired = store.redeemPairingCode(auth.deviceId, String(code ?? ''), actorKey);

      // Notify creator in real time
      sendToDevice(paired.creator.deviceId, {
        type: 'pairing:completed',
        conversation: {
          ...paired.conversation,
          peer: paired.redeemer,
          peerOnline: isDeviceOnline(paired.redeemer.deviceId),
        },
      });

      res.json({
        conversation: {
          ...paired.conversation,
          peer: paired.creator,
          peerOnline: isDeviceOnline(paired.creator.deviceId),
        },
      });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Code invalide.';
      const status = message.includes('Trop de tentatives') ? 429 : 400;
      res.status(status).json({ error: message });
    }
  });

  // 4. Conversations & settings
  app.get('/api/conversations', (req, res) => {
    const auth = authenticateRequest(req, res);
    if (!auth) return;
    const list = store.listConversationsForDevice(auth.deviceId).map(({ conversation, peer }) => ({
      ...conversation,
      peer,
      peerOnline: isDeviceOnline(peer.deviceId),
    }));
    res.json({ conversations: list });
  });

  app.patch('/api/conversations/:conversationId/settings', (req, res) => {
    const auth = authenticateRequest(req, res);
    if (!auth) return;
    const { conversationId } = req.params;
    if (!SAFE_ID_RE.test(conversationId)) {
      res.status(400).json({ error: 'Identifiant invalide.' });
      return;
    }
    try {
      const { ephemeralTtlMs, rotateKeyEpoch } = req.body ?? {};
      const updated = store.updateConversationSettings(conversationId, auth.deviceId, {
        ephemeralTtlMs,
        rotateKeyEpoch,
      });
      for (const participant of updated.participants) {
        sendToDevice(participant, {
          type: 'conversation:updated',
          conversationId: updated.conversationId,
          ephemeralTtlMs: updated.ephemeralTtlMs,
          keyEpoch: updated.keyEpoch,
          updatedAt: updated.updatedAt,
        });
      }
      res.json({ conversation: updated });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Erreur.';
      res.status(msg.includes('Accès refusé') ? 403 : 400).json({ error: msg });
    }
  });

  app.post('/api/conversations/:conversationId/revoke', async (req, res) => {
    const auth = authenticateRequest(req, res);
    if (!auth) return;
    const { conversationId } = req.params;
    if (!SAFE_ID_RE.test(conversationId)) {
      res.status(400).json({ error: 'Identifiant invalide.' });
      return;
    }
    try {
      const { conversation, deletedFileIds } = store.revokeConversation(conversationId, auth.deviceId);
      for (const fileId of deletedFileIds) {
        await unlinkBlobSafe(fileId);
      }
      for (const participant of conversation.participants) {
        sendToDevice(participant, {
          type: 'conversation:revoked',
          conversationId: conversation.conversationId,
          revokedBy: auth.deviceId,
        });
      }
      res.json({ conversation });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Erreur.';
      res.status(msg.includes('Accès refusé') ? 403 : 400).json({ error: msg });
    }
  });

  // 5. Encrypted messages (ciphertexts only; server never inspects or logs content)
  app.get('/api/conversations/:conversationId/messages', (req, res) => {
    const auth = authenticateRequest(req, res);
    if (!auth) return;
    const { conversationId } = req.params;
    if (!SAFE_ID_RE.test(conversationId)) {
      res.status(400).json({ error: 'Identifiant invalide.' });
      return;
    }
    try {
      const messages = store.getMessagesForConversation(conversationId, auth.deviceId);
      // Mark delivered for recipient
      for (const m of messages) {
        if (m.recipientDeviceId === auth.deviceId && m.status === 'sent') {
          const updated = store.markMessageDelivered(conversationId, m.messageId, auth.deviceId);
          if (updated) {
            sendToDevice(updated.senderDeviceId, {
              type: 'msg:delivered',
              conversationId,
              messageId: updated.messageId,
              deliveredAt: updated.deliveredAt,
            });
          }
        }
      }
      res.json({ messages });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Accès refusé.';
      res.status(msg.includes('Accès refusé') ? 403 : 404).json({ error: msg });
    }
  });

  app.post('/api/messages', (req, res) => {
    const auth = authenticateRequest(req, res);
    if (!auth) return;
    try {
      const envelope = req.body as Omit<ServerEncryptedMessage, 'status' | 'createdAt'>;
      const stored = store.storeEncryptedMessage(auth.deviceId, envelope);

      // Push encrypted envelope to recipient in real time
      sendToDevice(stored.recipientDeviceId, {
        type: 'msg:new',
        envelope: stored,
      });

      // If recipient has an open WebSocket, immediately mark delivered
      if (isDeviceOnline(stored.recipientDeviceId)) {
        const delivered = store.markMessageDelivered(
          stored.conversationId,
          stored.messageId,
          stored.recipientDeviceId
        );
        if (delivered) {
          sendToDevice(stored.senderDeviceId, {
            type: 'msg:delivered',
            conversationId: stored.conversationId,
            messageId: stored.messageId,
            deliveredAt: delivered.deliveredAt,
          });
        }
      }

      res.status(201).json({ message: stored });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Envoi refusé.';
      res.status(msg.includes('Accès refusé') ? 403 : 400).json({ error: msg });
    }
  });

  app.post('/api/conversations/:conversationId/messages/:messageId/read', async (req, res) => {
    const auth = authenticateRequest(req, res);
    if (!auth) return;
    const { conversationId, messageId } = req.params;
    if (!SAFE_ID_RE.test(conversationId) || !SAFE_ID_RE.test(messageId)) {
      res.status(400).json({ error: 'Identifiant invalide.' });
      return;
    }
    try {
      const result = store.markMessageRead(conversationId, messageId, auth.deviceId);
      if (!result) {
        res.status(404).json({ error: 'Message introuvable ou déjà expiré.' });
        return;
      }
      const { message, expiredImmediately } = result;

      sendToDevice(message.senderDeviceId, {
        type: 'msg:read',
        conversationId,
        messageId,
        readAt: message.readAt,
        expiresAt: message.expiresAt,
      });

      if (expiredImmediately) {
        if (message.fileId) {
          await unlinkBlobSafe(message.fileId);
        }
        sendToDevice(message.senderDeviceId, {
          type: 'msg:expired',
          conversationId,
          messageId,
        });
        sendToDevice(message.recipientDeviceId, {
          type: 'msg:expired',
          conversationId,
          messageId,
        });
      }

      res.json({ message, expiredImmediately });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Accès refusé.';
      res.status(msg.includes('Accès refusé') ? 403 : 400).json({ error: msg });
    }
  });

  // 6. Temporary encrypted binary file storage (client encrypts before upload)
  app.post(
    '/api/files/:conversationId',
    express.raw({ type: 'application/octet-stream', limit: '25mb' }),
    async (req, res) => {
      const auth = authenticateRequest(req, res);
      if (!auth) return;
      const { conversationId } = req.params;
      if (!SAFE_ID_RE.test(conversationId)) {
        res.status(400).json({ error: 'Identifiant de conversation invalide.' });
        return;
      }
      const buf = req.body;
      if (!Buffer.isBuffer(buf) || buf.length === 0) {
        res.status(400).json({ error: 'Contenu binaire chiffré requis.' });
        return;
      }
      try {
        const fileId = `fil_${crypto.randomBytes(12).toString('hex')}`;
        const rec = store.registerEncryptedFile({
          fileId,
          conversationId,
          uploaderDeviceId: auth.deviceId,
          byteLength: buf.length,
        });
        await fs.writeFile(path.join(BLOB_DIR, `${fileId}.enc`), buf);
        res.status(201).json({ fileId: rec.fileId, byteLength: rec.byteLength });
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Upload refusé.';
        res.status(msg.includes('Accès refusé') ? 403 : 400).json({ error: msg });
      }
    }
  );

  app.get('/api/files/:fileId', async (req, res) => {
    const auth = authenticateRequest(req, res);
    if (!auth) return;
    const { fileId } = req.params;
    if (!SAFE_ID_RE.test(fileId)) {
      res.status(400).json({ error: 'Identifiant fichier invalide.' });
      return;
    }
    try {
      store.getEncryptedFile(fileId, auth.deviceId);
      const data = await fs.readFile(path.join(BLOB_DIR, `${fileId}.enc`));
      res.setHeader('Content-Type', 'application/octet-stream');
      res.setHeader('Cache-Control', 'no-store');
      res.send(data);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Fichier indisponible.';
      res.status(msg.includes('Accès refusé') ? 403 : 404).json({ error: msg });
    }
  });

  // WebSocket authentication & presence
  wss.on('connection', (ws, req) => {
    const url = new URL(req.url || '/', `http://localhost:${PORT}`);
    const token = url.searchParams.get('token') || '';
    const session = store.verifySessionToken(token);
    if (!session) {
      ws.close(4001, 'Unauthorized');
      return;
    }

    const { deviceId } = session;
    let set = deviceSockets.get(deviceId);
    if (!set) {
      set = new Set();
      deviceSockets.set(deviceId, set);
    }
    set.add(ws);
    broadcastPresence(deviceId, true);

    ws.on('message', (raw) => {
      try {
        const parsed = JSON.parse(String(raw)) as { type?: string };
        if (parsed.type === 'ping') {
          ws.send(JSON.stringify({ type: 'pong', ts: Date.now() }));
        }
      } catch {
        // Ignore malformed frames
      }
    });

    ws.on('close', () => {
      const sockets = deviceSockets.get(deviceId);
      if (sockets) {
        sockets.delete(ws);
        if (sockets.size === 0) {
          deviceSockets.delete(deviceId);
          broadcastPresence(deviceId, false);
        }
      }
    });
  });

  // Automatic ephemeral sweep every 2 seconds
  const sweepTimer = setInterval(async () => {
    const { expiredMessages, expiredFileIds } = store.sweepExpired(Date.now());
    for (const fileId of expiredFileIds) {
      await unlinkBlobSafe(fileId);
    }
    for (const item of expiredMessages) {
      sendToDevice(item.senderDeviceId, {
        type: 'msg:expired',
        conversationId: item.conversationId,
        messageId: item.messageId,
      });
      sendToDevice(item.recipientDeviceId, {
        type: 'msg:expired',
        conversationId: item.conversationId,
        messageId: item.messageId,
      });
    }
  }, 2000);
  sweepTimer.unref();

  // Frontend serving: Vite dev middleware in development, static dist in production
  if (process.env.NODE_ENV === 'production') {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distDir, 'index.html'));
    });
  } else {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  server.listen(PORT, '0.0.0.0', () => {
    console.log(`eMesh server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start eMesh server:', err);
  process.exit(1);
});
