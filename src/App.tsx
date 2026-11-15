import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import type { User } from 'firebase/auth';
import {
  KeyRound,
  Lock,
  MessageSquare,
  Moon,
  QrCode,
  Settings,
  ShieldAlert,
  ShieldCheck,
  Sun,
  UserPlus,
  Users,
} from 'lucide-react';
import {
  authenticateDeviceSession,
  createPairingCodeApi,
  fetchConversationsApi,
  fetchMessagesApi,
  logoutDeviceSession,
  markMessageReadApi,
  redeemPairingCodeApi,
  revokeConversationApi,
  revokeServerIdentity,
  sendEncryptedMessageApi,
  updateConversationSettingsApi,
  updateServerPseudonym,
  uploadEncryptedBlobApi,
  type AuthSession,
  type WsServerEvent,
} from './api/emeshClient';
import {
  createDeviceIdentity,
  decryptEnvelope,
  encryptEnvelope,
  encryptFileBytes,
  generateId,
  toPublicIdentity,
  unwrapIdentityWithPin,
  wrapIdentityWithPin,
} from './crypto/emeshCrypto';
import {
  signInTechnicalGoogle,
  signOutTechnicalGoogle,
  subscribeFirebaseAuth,
  syncDeviceIdentityToFirestore,
} from './firebase';
import {
  getVerifiedPeerFingerprint,
  loadLocalMessages,
  loadPreferences,
  loadVaultRecord,
  purgeLocalConversation,
  saveLocalMessages,
  savePreferences,
  saveVaultRecord,
  saveVerifiedPeerFingerprint,
  wipeAllLocalVaultData,
} from './storage/localVault';
import { EmeshLogo } from './components/EmeshLogo';
import {
  CreateIdentityView,
  PinLockView,
  PinSetupView,
  SplashScreen,
} from './components/OnboardingScreens';
import {
  GenerateCodeView,
  JoinCodeView,
  ScanQrView,
  VerifyIdentityView,
} from './components/PairingViews';
import { ChatView } from './components/ChatView';
import {
  AssociationsView,
  DeleteAccountView,
  SettingsView,
} from './components/SettingsAndManagement';
import type {
  AppScreen,
  DecryptedMessage,
  EncryptedEnvelope,
  EphemeralDurationMs,
  MessageType,
  PeerConversation,
  UnlockedIdentity,
  WrappedVaultRecord,
} from './types';

export default function App() {
  const initialPrefs = useMemo(() => loadPreferences(), []);
  const [theme, setTheme] = useState<'dark' | 'light'>(initialPrefs.theme);
  const [defaultTtlMs, setDefaultTtlMs] = useState<EphemeralDurationMs>(
    initialPrefs.defaultEphemeralTtlMs
  );

  const [booting, setBooting] = useState(true);
  const [screen, setScreen] = useState<AppScreen>('splash');
  const [vault, setVault] = useState<WrappedVaultRecord | null>(null);
  const [pendingIdentity, setPendingIdentity] = useState<UnlockedIdentity | null>(null);
  const [identity, setIdentity] = useState<UnlockedIdentity | null>(null);
  const [session, setSession] = useState<AuthSession | null>(null);
  const [wsOnline, setWsOnline] = useState(false);

  const [conversations, setConversations] = useState<PeerConversation[]>([]);
  const [activeConversationId, setActiveConversationId] = useState<string | null>(null);
  const [messagesByConv, setMessagesByConv] = useState<Record<string, DecryptedMessage[]>>({});
  const [firebaseUser, setFirebaseUser] = useState<User | null>(null);
  const [globalError, setGlobalError] = useState<string | null>(null);

  const wsRef = useRef<WebSocket | null>(null);
  const ratchetCounterRef = useRef<Record<string, number>>({});
  const seenMsgIdsRef = useRef<Set<string>>(new Set());

  // Sync Tailwind dark class on <html>
  useEffect(() => {
    document.documentElement.classList.toggle('dark', theme === 'dark');
    savePreferences({ theme, defaultEphemeralTtlMs: defaultTtlMs });
  }, [theme, defaultTtlMs]);

  // Subscribe optional Firebase Auth state
  useEffect(() => {
    return subscribeFirebaseAuth(setFirebaseUser);
  }, []);

  // Load local IndexedDB vault at startup
  useEffect(() => {
    let active = true;
    const init = async () => {
      try {
        const existingVault = await loadVaultRecord();
        if (!active) return;
        setVault(existingVault);
        const params = new URLSearchParams(window.location.search);
        if (params.get('autostart') === '1') {
          setScreen(existingVault ? 'unlock-pin' : 'create-identity');
        } else {
          setScreen('splash');
        }
      } catch (err) {
        console.error(err);
      } finally {
        if (active) setBooting(false);
      }
    };
    void init();
    return () => {
      active = false;
    };
  }, []);

  const hydrateConversations = useCallback(async (authToken: string) => {
    const { conversations: serverList } = await fetchConversationsApi(authToken);
    const enriched = await Promise.all(
      serverList.map(async (conv) => {
        const verifiedFingerprint = await getVerifiedPeerFingerprint(conv.peer.deviceId);
        return {
          ...conv,
          verifiedFingerprint: verifiedFingerprint ?? undefined,
        };
      })
    );
    setConversations(enriched);
    setActiveConversationId((prev) => {
      if (prev && enriched.some((c) => c.conversationId === prev)) return prev;
      return enriched.find((c) => c.status === 'active')?.conversationId ?? enriched[0]?.conversationId ?? null;
    });
  }, []);

  const decryptAndMergeEnvelope = useCallback(
    async (
      envelope: EncryptedEnvelope,
      currentIdentity: UnlockedIdentity,
      conv: PeerConversation
    ) => {
      if (seenMsgIdsRef.current.has(envelope.messageId)) {
        return;
      }
      seenMsgIdsRef.current.add(envelope.messageId);

      if (envelope.senderDeviceId === currentIdentity.deviceId) {
        // Sender's own message is already saved locally in decrypted form when sent
        return;
      }

      try {
        const { payload, verifiedSignature } = await decryptEnvelope({
          receiver: currentIdentity,
          peer: conv.peer,
          envelope,
        });
        const item: DecryptedMessage = {
          messageId: envelope.messageId,
          conversationId: envelope.conversationId,
          senderDeviceId: envelope.senderDeviceId,
          recipientDeviceId: envelope.recipientDeviceId,
          isMine: false,
          messageType: envelope.messageType,
          payload,
          status: envelope.status,
          ephemeralTtlMs: envelope.ephemeralTtlMs,
          createdAt: envelope.createdAt,
          readAt: envelope.readAt,
          expiresAt: envelope.expiresAt,
          verifiedSignature,
          keyEpoch: envelope.keyEpoch,
          ratchetCounter: envelope.ratchetCounter,
        };
        setMessagesByConv((prev) => {
          const existing = prev[envelope.conversationId] ?? [];
          if (existing.some((m) => m.messageId === item.messageId)) return prev;
          const next = [...existing, item].sort((a, b) => a.createdAt - b.createdAt);
          void saveLocalMessages(envelope.conversationId, next);
          return { ...prev, [envelope.conversationId]: next };
        });
      } catch (err) {
        const fallback: DecryptedMessage = {
          messageId: envelope.messageId,
          conversationId: envelope.conversationId,
          senderDeviceId: envelope.senderDeviceId,
          recipientDeviceId: envelope.recipientDeviceId,
          isMine: false,
          messageType: envelope.messageType,
          payload: { text: '', nonce: '', sentAt: envelope.createdAt },
          status: envelope.status,
          ephemeralTtlMs: envelope.ephemeralTtlMs,
          createdAt: envelope.createdAt,
          verifiedSignature: false,
          keyEpoch: envelope.keyEpoch,
          ratchetCounter: envelope.ratchetCounter,
          decryptionError:
            err instanceof Error ? err.message : 'Impossible de déchiffrer ce message.',
        };
        setMessagesByConv((prev) => ({
          ...prev,
          [envelope.conversationId]: [...(prev[envelope.conversationId] ?? []), fallback],
        }));
      }
    },
    []
  );

  // Fetch conversation history when activeConversationId changes
  useEffect(() => {
    if (!session || !identity || !activeConversationId) return;
    const conv = conversations.find((c) => c.conversationId === activeConversationId);
    if (!conv) return;

    let cancelled = false;
    const syncHistory = async () => {
      const localCached = await loadLocalMessages(activeConversationId);
      if (!cancelled && localCached.length > 0) {
        setMessagesByConv((prev) => {
          const cur = prev[activeConversationId] ?? [];
          const mergedMap = new Map<string, DecryptedMessage>();
          for (const m of [...localCached, ...cur]) mergedMap.set(m.messageId, m);
          return {
            ...prev,
            [activeConversationId]: Array.from(mergedMap.values()).sort(
              (a, b) => a.createdAt - b.createdAt
            ),
          };
        });
      }

      try {
        const { messages: serverEnvelopes } = await fetchMessagesApi(
          session.token,
          activeConversationId
        );
        if (cancelled) return;
        for (const env of serverEnvelopes) {
          await decryptAndMergeEnvelope(env, identity, conv);
          // Sync status updates for sent messages
          setMessagesByConv((prev) => {
            const list = prev[activeConversationId] ?? [];
            const idx = list.findIndex((m) => m.messageId === env.messageId);
            if (idx === -1) return prev;
            const copy = [...list];
            copy[idx] = {
              ...copy[idx],
              status: env.status,
              readAt: env.readAt ?? copy[idx].readAt,
              expiresAt: env.expiresAt ?? copy[idx].expiresAt,
            };
            return { ...prev, [activeConversationId]: copy };
          });
        }
      } catch (err) {
        console.error(err);
      }
    };
    void syncHistory();
    return () => {
      cancelled = true;
    };
  }, [activeConversationId, session, identity, conversations.length, decryptAndMergeEnvelope]);

  // WebSocket real-time connection
  useEffect(() => {
    if (!session || !identity) return;
    let closedByUs = false;
    let reconnectTimer: number | null = null;
    let pingTimer: number | null = null;

    const connect = () => {
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const wsUrl = `${proto}//${window.location.host}/ws?token=${encodeURIComponent(session.token)}`;
      const ws = new WebSocket(wsUrl);
      wsRef.current = ws;

      ws.onopen = () => {
        setWsOnline(true);
        pingTimer = window.setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: 'ping' }));
          }
        }, 25000);
      };

      ws.onmessage = async (event) => {
        try {
          const data = JSON.parse(String(event.data)) as WsServerEvent;
          if (data.type === 'presence:update') {
            setConversations((prev) =>
              prev.map((c) =>
                c.conversationId === data.conversationId ? { ...c, peerOnline: data.online } : c
              )
            );
          } else if (data.type === 'pairing:completed') {
            const verifiedFp = await getVerifiedPeerFingerprint(data.conversation.peer.deviceId);
            const enriched: PeerConversation = {
              ...data.conversation,
              verifiedFingerprint: verifiedFp ?? undefined,
            };
            setConversations((prev) => [
              enriched,
              ...prev.filter((c) => c.conversationId !== enriched.conversationId),
            ]);
            setActiveConversationId(enriched.conversationId);
            setScreen('verify-identity');
          } else if (data.type === 'msg:new') {
            setConversations((prev) => {
              const target = prev.find((c) => c.conversationId === data.envelope.conversationId);
              if (target) {
                void decryptAndMergeEnvelope(data.envelope, identity, target);
              }
              return prev;
            });
          } else if (data.type === 'msg:delivered') {
            setMessagesByConv((prev) => {
              const list = prev[data.conversationId];
              if (!list) return prev;
              const next = list.map((m) =>
                m.messageId === data.messageId && m.status === 'sent'
                  ? { ...m, status: 'delivered' as const }
                  : m
              );
              void saveLocalMessages(data.conversationId, next);
              return { ...prev, [data.conversationId]: next };
            });
          } else if (data.type === 'msg:read') {
            setMessagesByConv((prev) => {
              const list = prev[data.conversationId];
              if (!list) return prev;
              const next = list.map((m) =>
                m.messageId === data.messageId
                  ? {
                      ...m,
                      status: 'read' as const,
                      readAt: data.readAt,
                      expiresAt: data.expiresAt,
                    }
                  : m
              );
              void saveLocalMessages(data.conversationId, next);
              return { ...prev, [data.conversationId]: next };
            });
          } else if (data.type === 'msg:expired') {
            setMessagesByConv((prev) => {
              const list = prev[data.conversationId];
              if (!list) return prev;
              const next = list.filter((m) => m.messageId !== data.messageId);
              void saveLocalMessages(data.conversationId, next);
              return { ...prev, [data.conversationId]: next };
            });
          } else if (data.type === 'conversation:updated') {
            setConversations((prev) =>
              prev.map((c) =>
                c.conversationId === data.conversationId
                  ? {
                      ...c,
                      ephemeralTtlMs: data.ephemeralTtlMs,
                      keyEpoch: data.keyEpoch,
                      updatedAt: data.updatedAt,
                    }
                  : c
              )
            );
          } else if (data.type === 'conversation:revoked') {
            setConversations((prev) =>
              prev.map((c) =>
                c.conversationId === data.conversationId ? { ...c, status: 'revoked' } : c
              )
            );
            setMessagesByConv((prev) => ({ ...prev, [data.conversationId]: [] }));
            void purgeLocalConversation(data.conversationId);
          }
        } catch {
          // ignore non-app frames
        }
      };

      ws.onclose = () => {
        setWsOnline(false);
        if (pingTimer) clearInterval(pingTimer);
        if (!closedByUs) {
          reconnectTimer = window.setTimeout(connect, 2500);
        }
      };
    };

    connect();
    return () => {
      closedByUs = true;
      if (pingTimer) clearInterval(pingTimer);
      if (reconnectTimer) clearTimeout(reconnectTimer);
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, [session, identity, decryptAndMergeEnvelope]);

  // Local 1-second sweep to auto-delete expired ephemeral messages
  useEffect(() => {
    const timer = window.setInterval(() => {
      const now = Date.now();
      setMessagesByConv((prev) => {
        let changed = false;
        const nextMap: Record<string, DecryptedMessage[]> = {};
        for (const [convId, list] of Object.entries(prev)) {
          const filtered = list.filter(
            (m) => !(typeof m.expiresAt === 'number' && m.status === 'read' && now >= m.expiresAt)
          );
          if (filtered.length !== list.length) {
            changed = true;
            void saveLocalMessages(convId, filtered);
          }
          nextMap[convId] = filtered;
        }
        return changed ? nextMap : prev;
      });
    }, 1000);
    return () => clearInterval(timer);
  }, []);

  const openSessionForIdentity = async (unlocked: UnlockedIdentity) => {
    const authSess = await authenticateDeviceSession(unlocked);
    setIdentity(unlocked);
    setSession(authSess);
    await hydrateConversations(authSess.token);
    if (firebaseUser) {
      void syncDeviceIdentityToFirestore(toPublicIdentity(unlocked)).catch(console.error);
    }
  };

  const handlePinSetupComplete = async (pin: string) => {
    if (!pendingIdentity) return;
    const wrapped = await wrapIdentityWithPin(pendingIdentity, pin);
    await saveVaultRecord(wrapped);
    setVault(wrapped);
    await openSessionForIdentity(pendingIdentity);
    setPendingIdentity(null);
    setScreen('home');
  };

  const handleUnlockWithPin = async (pin: string) => {
    if (!vault) throw new Error('Aucun coffre trouvé.');
    const unlocked = await unwrapIdentityWithPin(vault, pin);
    await openSessionForIdentity(unlocked);
    setScreen('home');
  };

  const handleRedeemPairingCode = async (code: string) => {
    if (!session) return;
    const { conversation } = await redeemPairingCodeApi(session.token, code);
    const verifiedFp = await getVerifiedPeerFingerprint(conversation.peer.deviceId);
    const enriched: PeerConversation = {
      ...conversation,
      verifiedFingerprint: verifiedFp ?? undefined,
    };
    setConversations((prev) => [
      enriched,
      ...prev.filter((c) => c.conversationId !== enriched.conversationId),
    ]);
    setActiveConversationId(enriched.conversationId);
    setScreen('verify-identity');
  };

  const handleConfirmPeerVerified = async (peerDeviceId: string, fingerprint: string) => {
    await saveVerifiedPeerFingerprint(peerDeviceId, fingerprint);
    setConversations((prev) =>
      prev.map((c) =>
        c.peer.deviceId === peerDeviceId ? { ...c, verifiedFingerprint: fingerprint } : c
      )
    );
  };

  const activeConversation = useMemo(
    () => conversations.find((c) => c.conversationId === activeConversationId) ?? null,
    [conversations, activeConversationId]
  );

  const handleSendText = async (text: string, ttl: EphemeralDurationMs) => {
    if (!identity || !session || !activeConversation) return;
    const convId = activeConversation.conversationId;
    const nextCounter = (ratchetCounterRef.current[convId] ?? 0) + 1;
    ratchetCounterRef.current[convId] = nextCounter;

    const payload = {
      text,
      nonce: generateId('nc'),
      sentAt: Date.now(),
    };
    const envelope = await encryptEnvelope({
      sender: identity,
      peer: activeConversation.peer,
      conversationId: convId,
      messageType: 'text',
      payload,
      ephemeralTtlMs: ttl,
      keyEpoch: activeConversation.keyEpoch,
      ratchetCounter: nextCounter,
    });

    seenMsgIdsRef.current.add(envelope.messageId);
    const { message: stored } = await sendEncryptedMessageApi(session.token, envelope);
    const localMsg: DecryptedMessage = {
      messageId: stored.messageId,
      conversationId: convId,
      senderDeviceId: identity.deviceId,
      recipientDeviceId: activeConversation.peer.deviceId,
      isMine: true,
      messageType: 'text',
      payload,
      status: stored.status,
      ephemeralTtlMs: ttl,
      createdAt: stored.createdAt,
      verifiedSignature: true,
      keyEpoch: stored.keyEpoch,
      ratchetCounter: stored.ratchetCounter,
    };
    setMessagesByConv((prev) => {
      const next = [...(prev[convId] ?? []), localMsg];
      void saveLocalMessages(convId, next);
      return { ...prev, [convId]: next };
    });
  };

  const handleSendMedia = async (params: {
    fileBytes: Uint8Array;
    mimeType: string;
    fileName: string;
    messageType: Exclude<MessageType, 'text'>;
    ttl: EphemeralDurationMs;
    durationMs?: number;
  }) => {
    if (!identity || !session || !activeConversation) return;
    const convId = activeConversation.conversationId;
    const { encryptedBytes, fileKeyB64, fileIvB64 } = await encryptFileBytes(params.fileBytes);
    const { fileId } = await uploadEncryptedBlobApi(session.token, convId, encryptedBytes);

    const nextCounter = (ratchetCounterRef.current[convId] ?? 0) + 1;
    ratchetCounterRef.current[convId] = nextCounter;

    const payload = {
      media: {
        fileId,
        fileKeyB64,
        fileIvB64,
        mimeType: params.mimeType,
        fileName: params.fileName,
        fileSize: params.fileBytes.byteLength,
        durationMs: params.durationMs,
      },
      nonce: generateId('nc'),
      sentAt: Date.now(),
    };

    const envelope = await encryptEnvelope({
      sender: identity,
      peer: activeConversation.peer,
      conversationId: convId,
      messageType: params.messageType,
      payload,
      ephemeralTtlMs: params.ttl,
      keyEpoch: activeConversation.keyEpoch,
      ratchetCounter: nextCounter,
      fileId,
    });

    seenMsgIdsRef.current.add(envelope.messageId);
    const { message: stored } = await sendEncryptedMessageApi(session.token, envelope);
    const localMsg: DecryptedMessage = {
      messageId: stored.messageId,
      conversationId: convId,
      senderDeviceId: identity.deviceId,
      recipientDeviceId: activeConversation.peer.deviceId,
      isMine: true,
      messageType: params.messageType,
      payload,
      status: stored.status,
      ephemeralTtlMs: params.ttl,
      createdAt: stored.createdAt,
      verifiedSignature: true,
      keyEpoch: stored.keyEpoch,
      ratchetCounter: stored.ratchetCounter,
    };
    setMessagesByConv((prev) => {
      const next = [...(prev[convId] ?? []), localMsg];
      void saveLocalMessages(convId, next);
      return { ...prev, [convId]: next };
    });
  };

  const handleMarkRead = useCallback(
    async (messageId: string) => {
      if (!session || !activeConversationId) return;
      try {
        const res = await markMessageReadApi(session.token, activeConversationId, messageId);
        setMessagesByConv((prev) => {
          const list = prev[activeConversationId] ?? [];
          const next = res.expiredImmediately
            ? list.map((m) =>
                m.messageId === messageId
                  ? { ...m, status: 'read' as const, readAt: res.message.readAt }
                  : m
              )
            : list.map((m) =>
                m.messageId === messageId
                  ? {
                      ...m,
                      status: 'read' as const,
                      readAt: res.message.readAt,
                      expiresAt: res.message.expiresAt,
                    }
                  : m
              );
          void saveLocalMessages(activeConversationId, next);
          return { ...prev, [activeConversationId]: next };
        });
      } catch {
        // Ignore if already expired
      }
    },
    [session, activeConversationId]
  );

  const handleDestroyInstantMessage = (messageId: string) => {
    if (!activeConversationId) return;
    setMessagesByConv((prev) => {
      const next = (prev[activeConversationId] ?? []).filter((m) => m.messageId !== messageId);
      void saveLocalMessages(activeConversationId, next);
      return { ...prev, [activeConversationId]: next };
    });
  };

  const handleLockDevice = async () => {
    if (session) {
      await logoutDeviceSession(session.token).catch(() => {});
    }
    wsRef.current?.close();
    setSession(null);
    setIdentity(null);
    setMessagesByConv({});
    setScreen('unlock-pin');
  };

  const handleDeleteIdentity = async () => {
    if (session) {
      await revokeServerIdentity(session.token).catch(() => {});
    }
    wsRef.current?.close();
    await wipeAllLocalVaultData();
    setSession(null);
    setIdentity(null);
    setVault(null);
    setConversations([]);
    setMessagesByConv({});
    setActiveConversationId(null);
    setScreen('splash');
  };

  if (booting) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50 dark:bg-[#050811] text-slate-500 text-sm">
        Initialisation du coffre eMesh…
      </div>
    );
  }

  // Unauthenticated / Onboarding screens
  if (screen === 'splash') {
    return (
      <SplashScreen
        hasExistingVault={!!vault}
        theme={theme}
        onToggleTheme={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
        onStartCreate={() => setScreen('create-identity')}
        onGoUnlock={() => setScreen('unlock-pin')}
      />
    );
  }

  if (screen === 'create-identity') {
    return (
      <CreateIdentityView
        onBack={() => setScreen('splash')}
        generateIdentity={createDeviceIdentity}
        onIdentityGenerated={(gen) => {
          setPendingIdentity(gen);
          setScreen('setup-pin');
        }}
      />
    );
  }

  if (screen === 'setup-pin' && pendingIdentity) {
    return <PinSetupView identity={pendingIdentity} onComplete={handlePinSetupComplete} />;
  }

  if (screen === 'unlock-pin' && vault) {
    return (
      <PinLockView
        vault={vault}
        onUnlock={handleUnlockWithPin}
        onGoDeleteAccount={() => setScreen('delete-account')}
      />
    );
  }

  if (screen === 'delete-account' && !identity) {
    return (
      <DeleteAccountView
        hasSession={false}
        onConfirmDelete={handleDeleteIdentity}
        onBack={() => setScreen(vault ? 'unlock-pin' : 'splash')}
      />
    );
  }

  if (!identity || !session) {
    return (
      <SplashScreen
        hasExistingVault={!!vault}
        theme={theme}
        onToggleTheme={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
        onStartCreate={() => setScreen('create-identity')}
        onGoUnlock={() => setScreen('unlock-pin')}
      />
    );
  }

  // Authenticated Workspace Shell (Responsive Desktop 2-Column + Mobile Thumb Navigation)
  return (
    <div className="h-screen flex flex-col bg-slate-50 dark:bg-[#050811] text-slate-950 dark:text-slate-50 overflow-hidden">
      {/* Compact Top Bar (<= 56px; hidden on mobile when inside ChatView to maximize conversation space) */}
      <header
        className={`shrink-0 h-14 px-4 sm:px-6 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] items-center justify-between gap-4 ${
          screen === 'chat' ? 'hidden md:flex' : 'flex'
        }`}
      >
        <button
          type="button"
          onClick={() => setScreen('home')}
          className="flex items-center gap-2.5 shrink-0 text-left"
        >
          <EmeshLogo size={30} />
          <span className="font-display text-lg font-bold tracking-tight whitespace-nowrap">
            eMesh
          </span>
        </button>

        <nav className="hidden md:flex items-center gap-6 text-sm font-medium text-slate-600 dark:text-slate-300">
          <button
            type="button"
            onClick={() => setScreen('home')}
            className={`whitespace-nowrap shrink-0 hover:text-slate-950 dark:hover:text-white ${
              screen === 'home' || screen === 'chat' ? 'text-blue-700 dark:text-blue-400' : ''
            }`}
          >
            Discussions
          </button>
          <button
            type="button"
            onClick={() => setScreen('generate-code')}
            className={`whitespace-nowrap shrink-0 hover:text-slate-950 dark:hover:text-white ${
              screen === 'generate-code' ? 'text-blue-700 dark:text-blue-400' : ''
            }`}
          >
            Connecter
          </button>
          <button
            type="button"
            onClick={() => setScreen('join-code')}
            className={`whitespace-nowrap shrink-0 hover:text-slate-950 dark:hover:text-white ${
              screen === 'join-code' || screen === 'scan-qr' ? 'text-blue-700 dark:text-blue-400' : ''
            }`}
          >
            Rejoindre
          </button>
          <button
            type="button"
            onClick={() => setScreen('associations')}
            className={`whitespace-nowrap shrink-0 hover:text-slate-950 dark:hover:text-white ${
              screen === 'associations' ? 'text-blue-700 dark:text-blue-400' : ''
            }`}
          >
            Associations
          </button>
          <button
            type="button"
            onClick={() => setScreen('settings')}
            className={`whitespace-nowrap shrink-0 hover:text-slate-950 dark:hover:text-white ${
              screen === 'settings' ? 'text-blue-700 dark:text-blue-400' : ''
            }`}
          >
            Paramètres
          </button>
        </nav>

        <div className="flex items-center gap-2 shrink-0">
          <button
            type="button"
            onClick={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
            aria-label={theme === 'dark' ? 'Mode clair' : 'Mode sombre'}
            className="min-h-[40px] min-w-[40px] rounded-xl border border-slate-200 dark:border-slate-800 flex items-center justify-center hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
          </button>
          <button
            type="button"
            onClick={() => void handleLockDevice()}
            aria-label="Verrouiller l’appareil"
            className="min-h-[40px] px-3 rounded-xl bg-[#0A1433] dark:bg-blue-600 text-white text-xs font-medium flex items-center gap-1.5 hover:bg-[#112254] dark:hover:bg-blue-500 whitespace-nowrap"
          >
            <Lock className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Verrouiller</span>
          </button>
        </div>
      </header>

      {globalError && (
        <div className="bg-red-600 text-white text-xs px-4 py-2 text-center">
          {globalError}
        </div>
      )}

      {/* Main Content Area */}
      <div className="flex-1 min-h-0 flex overflow-hidden">
        {/* Desktop Sidebar: Paired Conversations */}
        <aside className="hidden md:flex md:w-80 lg:w-96 shrink-0 flex-col border-r border-slate-200 dark:border-slate-800 bg-white dark:bg-[#080E21]">
          <div className="p-4 border-b border-slate-100 dark:border-slate-800 space-y-3">
            <div className="flex items-center justify-between gap-2">
              <div className="min-w-0">
                <p className="text-xs text-slate-500 dark:text-slate-400">Identité locale</p>
                <p className="font-display font-semibold text-sm truncate">{identity.pseudonym}</p>
              </div>
              <span className="text-xs text-slate-500 dark:text-slate-400 shrink-0">
                {wsOnline ? 'Temps réel actif' : 'Reconnexion…'}
              </span>
            </div>

            <button
              type="button"
              onClick={() => setScreen('generate-code')}
              className="w-full min-h-[44px] px-4 rounded-xl bg-[#0A1433] dark:bg-blue-600 text-white text-sm font-medium flex items-center justify-center gap-2 hover:bg-[#112254] dark:hover:bg-blue-500"
            >
              <UserPlus className="w-4 h-4" />
              Connecter un correspondant
            </button>
          </div>

          <div className="flex-1 overflow-y-auto divide-y divide-slate-100 dark:divide-slate-800/70">
            {conversations.length === 0 ? (
              <div className="p-6 text-center text-xs text-slate-500 dark:text-slate-400 space-y-2">
                <p>Aucune conversation privée active.</p>
                <p>Générez un code unique ou entrez celui de votre correspondant.</p>
              </div>
            ) : (
              conversations.map((conv) => {
                const selected =
                  conv.conversationId === activeConversationId &&
                  (screen === 'chat' || screen === 'home');
                const verified = conv.verifiedFingerprint === conv.peer.fingerprint;
                return (
                  <button
                    key={conv.conversationId}
                    type="button"
                    onClick={() => {
                      setActiveConversationId(conv.conversationId);
                      setScreen('chat');
                    }}
                    className={`w-full p-4 text-left flex items-center justify-between gap-3 transition-colors ${
                      selected
                        ? 'bg-blue-50 dark:bg-[#0F1B3D]'
                        : 'hover:bg-slate-50 dark:hover:bg-slate-900/40'
                    }`}
                  >
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-display font-semibold text-sm truncate">
                          {conv.peer.pseudonym}
                        </span>
                        {conv.peerOnline && conv.status === 'active' && (
                          <span className="w-2 h-2 rounded-full bg-emerald-500 shrink-0" />
                        )}
                      </div>
                      <p className="text-xs text-slate-500 dark:text-slate-400 truncate mt-0.5">
                        {conv.status === 'revoked'
                          ? 'Révoquée'
                          : verified
                          ? 'Identité vérifiée'
                          : 'À vérifier'}
                      </p>
                    </div>
                    {verified ? (
                      <ShieldCheck className="w-4 h-4 text-emerald-500 shrink-0" />
                    ) : (
                      <ShieldAlert className="w-4 h-4 text-amber-500 shrink-0" />
                    )}
                  </button>
                );
              })
            )}
          </div>
        </aside>

        {/* Active View Pane */}
        <main
          className={`flex-1 min-w-0 overflow-y-auto md:pb-0 ${
            screen === 'chat' ? 'pb-0' : 'pb-16'
          }`}
        >
          {screen === 'generate-code' && (
            <GenerateCodeView
              onCreateCode={() => createPairingCodeApi(session.token)}
              onBack={() => setScreen('home')}
            />
          )}

          {screen === 'join-code' && (
            <JoinCodeView
              onRedeemCode={handleRedeemPairingCode}
              onOpenScanner={() => setScreen('scan-qr')}
              onBack={() => setScreen('home')}
            />
          )}

          {screen === 'scan-qr' && (
            <ScanQrView
              onRedeemCode={handleRedeemPairingCode}
              onGoManualCode={() => setScreen('join-code')}
              onBack={() => setScreen('home')}
            />
          )}

          {screen === 'verify-identity' && activeConversation && (
            <VerifyIdentityView
              identity={identity}
              conversation={activeConversation}
              onConfirmVerified={handleConfirmPeerVerified}
              onOpenChat={() => setScreen('chat')}
              onBack={() => setScreen('chat')}
            />
          )}

          {screen === 'settings' && (
            <SettingsView
              identity={identity}
              theme={theme}
              defaultEphemeralTtlMs={defaultTtlMs}
              firebaseUser={firebaseUser}
              onToggleTheme={() => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))}
              onUpdatePseudonym={async (name) => {
                await updateServerPseudonym(session.token, name);
                const updated = { ...identity, pseudonym: name };
                setIdentity(updated);
                if (vault) {
                  const nextVault = { ...vault, pseudonym: name };
                  await saveVaultRecord(nextVault);
                  setVault(nextVault);
                }
              }}
              onChangePin={async (curPin, newPin) => {
                if (!vault) throw new Error('Coffre introuvable.');
                await unwrapIdentityWithPin(vault, curPin);
                const rewrapped = await wrapIdentityWithPin(identity, newPin);
                await saveVaultRecord(rewrapped);
                setVault(rewrapped);
              }}
              onChangeDefaultTtl={setDefaultTtlMs}
              onFirebaseLogin={async () => {
                await signInTechnicalGoogle();
                await syncDeviceIdentityToFirestore(toPublicIdentity(identity));
              }}
              onFirebaseLogout={signOutTechnicalGoogle}
              onOpenAssociations={() => setScreen('associations')}
              onLockDevice={handleLockDevice}
              onOpenDeleteAccount={() => setScreen('delete-account')}
              onBack={() => setScreen('home')}
            />
          )}

          {screen === 'associations' && (
            <AssociationsView
              conversations={conversations}
              onVerifyPeer={(conv) => {
                setActiveConversationId(conv.conversationId);
                setScreen('verify-identity');
              }}
              onOpenChat={(conv) => {
                setActiveConversationId(conv.conversationId);
                setScreen('chat');
              }}
              onRevokeConversation={async (id) => {
                await revokeConversationApi(session.token, id);
                setConversations((prev) =>
                  prev.map((c) => (c.conversationId === id ? { ...c, status: 'revoked' } : c))
                );
                setMessagesByConv((prev) => ({ ...prev, [id]: [] }));
                await purgeLocalConversation(id);
              }}
              onBack={() => setScreen('home')}
            />
          )}

          {screen === 'delete-account' && (
            <DeleteAccountView
              hasSession={true}
              onConfirmDelete={handleDeleteIdentity}
              onBack={() => setScreen('settings')}
            />
          )}

          {screen === 'chat' && activeConversation && (
            <ChatView
              conversation={activeConversation}
              messages={messagesByConv[activeConversation.conversationId] ?? []}
              authToken={session.token}
              isOnline={wsOnline}
              onBack={() => setScreen('home')}
              onOpenVerify={() => setScreen('verify-identity')}
              onUpdateTtl={async (ttl) => {
                const { conversation: updated } = await updateConversationSettingsApi(
                  session.token,
                  activeConversation.conversationId,
                  { ephemeralTtlMs: ttl }
                );
                setConversations((prev) =>
                  prev.map((c) =>
                    c.conversationId === updated.conversationId
                      ? { ...c, ephemeralTtlMs: updated.ephemeralTtlMs }
                      : c
                  )
                );
              }}
              onRotateKeyEpoch={async () => {
                const { conversation: updated } = await updateConversationSettingsApi(
                  session.token,
                  activeConversation.conversationId,
                  { rotateKeyEpoch: true }
                );
                setConversations((prev) =>
                  prev.map((c) =>
                    c.conversationId === updated.conversationId
                      ? { ...c, keyEpoch: updated.keyEpoch }
                      : c
                  )
                );
              }}
              onSendText={handleSendText}
              onSendMedia={handleSendMedia}
              onMarkRead={handleMarkRead}
              onDestroyInstantMessage={handleDestroyInstantMessage}
            />
          )}

          {screen === 'home' && (
            <div className="max-w-3xl mx-auto p-4 sm:p-8 space-y-8">
              <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] p-6 sm:p-8 space-y-6">
                <div className="space-y-2">
                  <p className="text-xs font-medium text-blue-700 dark:text-blue-400">
                    Connecté en tant que {identity.pseudonym} · Clés locales déverrouillées
                  </p>
                  <h1 className="font-display text-2xl sm:text-3xl font-bold text-slate-950 dark:text-white">
                    Prêt pour une communication privée
                  </h1>
                  <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
                    Chaque conversation associe exclusivement deux appareils grâce à un code unique
                    temporaire. Aucune troisième personne ne peut rejoindre l’échange.
                  </p>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                  <button
                    type="button"
                    onClick={() => setScreen('generate-code')}
                    className="min-h-[48px] px-4 py-3 rounded-xl bg-[#0A1433] dark:bg-blue-600 text-white text-sm font-medium flex items-center justify-center gap-2 hover:bg-[#112254] dark:hover:bg-blue-500"
                  >
                    <UserPlus className="w-4 h-4" />
                    Connecter un correspondant
                  </button>
                  <button
                    type="button"
                    onClick={() => setScreen('join-code')}
                    className="min-h-[48px] px-4 py-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#050811] text-sm font-medium flex items-center justify-center gap-2 hover:bg-slate-100 dark:hover:bg-slate-800"
                  >
                    <KeyRound className="w-4 h-4" />
                    Rejoindre avec un code
                  </button>
                  <button
                    type="button"
                    onClick={() => setScreen('scan-qr')}
                    className="min-h-[48px] px-4 py-3 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#050811] text-sm font-medium flex items-center justify-center gap-2 hover:bg-slate-100 dark:hover:bg-slate-800"
                  >
                    <QrCode className="w-4 h-4" />
                    Scanner un QR code
                  </button>
                </div>
              </div>

              {/* Mobile / Tablet conversation list (on desktop it's also in sidebar) */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h2 className="font-display text-lg font-semibold">
                    Correspondants associés ({conversations.length})
                  </h2>
                  <button
                    type="button"
                    onClick={() => setScreen('associations')}
                    className="text-xs font-medium text-blue-700 dark:text-blue-400 hover:underline"
                  >
                    Gérer les associations
                  </button>
                </div>

                {conversations.length === 0 ? (
                  <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] p-6 text-sm text-slate-500 dark:text-slate-400">
                    Aucune association active pour le moment. Cliquez sur « Connecter un
                    correspondant » pour obtenir votre code unique et QR code.
                  </div>
                ) : (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    {conversations.map((conv) => {
                      const verified = conv.verifiedFingerprint === conv.peer.fingerprint;
                      return (
                        <button
                          key={conv.conversationId}
                          type="button"
                          onClick={() => {
                            setActiveConversationId(conv.conversationId);
                            setScreen('chat');
                          }}
                          className="p-4 rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] text-left flex items-center justify-between gap-3 hover:border-blue-500 transition-colors"
                        >
                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="font-display font-semibold truncate">
                                {conv.peer.pseudonym}
                              </span>
                              {conv.peerOnline && conv.status === 'active' && (
                                <span className="w-2 h-2 rounded-full bg-emerald-500 shrink-0" />
                              )}
                            </div>
                            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
                              {conv.status === 'revoked'
                                ? 'Révoquée'
                                : verified
                                ? 'Empreinte vérifiée'
                                : 'Vérification recommandée'}
                            </p>
                          </div>
                          <MessageSquare className="w-4 h-4 text-blue-600 dark:text-blue-400 shrink-0" />
                        </button>
                      );
                    })}
                  </div>
                )}
              </div>
            </div>
          )}
        </main>
      </div>

      {/* Mobile Bottom Navigation Bar (<= 64px, Thumb Zone; hidden inside active chat) */}
      {screen !== 'chat' && (
        <nav
          aria-label="Navigation mobile"
          className="md:hidden fixed bottom-0 left-0 right-0 z-40 h-16 border-t border-slate-200 dark:border-slate-800 bg-white/95 dark:bg-[#0A1128]/95 backdrop-blur-md grid grid-cols-4 items-center"
        >
        <button
          type="button"
          onClick={() => setScreen('home')}
          className={`h-full flex flex-col items-center justify-center gap-1 text-[11px] font-medium ${
            screen === 'home'
              ? 'text-blue-700 dark:text-blue-400'
              : 'text-slate-500 dark:text-slate-400'
          }`}
        >
          <MessageSquare className="w-5 h-5" />
          <span>Accueil</span>
        </button>
        <button
          type="button"
          onClick={() => setScreen('generate-code')}
          className={`h-full flex flex-col items-center justify-center gap-1 text-[11px] font-medium ${
            screen === 'generate-code'
              ? 'text-blue-700 dark:text-blue-400'
              : 'text-slate-500 dark:text-slate-400'
          }`}
        >
          <UserPlus className="w-5 h-5" />
          <span>Connecter</span>
        </button>
        <button
          type="button"
          onClick={() => setScreen('join-code')}
          className={`h-full flex flex-col items-center justify-center gap-1 text-[11px] font-medium ${
            screen === 'join-code' || screen === 'scan-qr'
              ? 'text-blue-700 dark:text-blue-400'
              : 'text-slate-500 dark:text-slate-400'
          }`}
        >
          <QrCode className="w-5 h-5" />
          <span>Rejoindre</span>
        </button>
        <button
          type="button"
          onClick={() => setScreen('settings')}
          className={`h-full flex flex-col items-center justify-center gap-1 text-[11px] font-medium ${
            screen === 'settings' || screen === 'associations'
              ? 'text-blue-700 dark:text-blue-400'
              : 'text-slate-500 dark:text-slate-400'
          }`}
        >
          <Settings className="w-5 h-5" />
          <span>Paramètres</span>
        </button>
      </nav>
      )}
    </div>
  );
}
