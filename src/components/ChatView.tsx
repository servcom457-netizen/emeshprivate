import React, { useEffect, useRef, useState } from 'react';
import {
  ArrowLeft,
  Camera,
  Check,
  CheckCheck,
  Clock,
  Download,
  Eye,
  FileText,
  Image as ImageIcon,
  KeyRound,
  Mic,
  Paperclip,
  RefreshCw,
  Send,
  ShieldAlert,
  ShieldCheck,
  Square,
  Trash2,
  Video,
  X,
} from 'lucide-react';
import { decryptFileBytes } from '../crypto/emeshCrypto';
import { downloadEncryptedBlobApi } from '../api/emeshClient';
import { EPHEMERAL_OPTIONS } from '../types';
import type {
  DecryptedMessage,
  EphemeralDurationMs,
  MessageType,
  PeerConversation,
} from '../types';

interface ChatViewProps {
  conversation: PeerConversation;
  messages: DecryptedMessage[];
  authToken: string;
  isOnline: boolean;
  onBack?: () => void;
  onOpenVerify: () => void;
  onUpdateTtl: (ttl: EphemeralDurationMs) => Promise<void>;
  onRotateKeyEpoch: () => Promise<void>;
  onSendText: (text: string, ttl: EphemeralDurationMs) => Promise<void>;
  onSendMedia: (params: {
    fileBytes: Uint8Array;
    mimeType: string;
    fileName: string;
    messageType: Exclude<MessageType, 'text'>;
    ttl: EphemeralDurationMs;
    durationMs?: number;
  }) => Promise<void>;
  onMarkRead: (messageId: string) => Promise<void>;
  onDestroyInstantMessage: (messageId: string) => void;
}

function formatDurationClock(ms: number): string {
  const totalSec = Math.max(0, Math.round(ms / 1000));
  if (totalSec >= 3600) {
    const h = Math.floor(totalSec / 3600);
    const m = Math.floor((totalSec % 3600) / 60);
    return `${h}h ${String(m).padStart(2, '0')}m`;
  }
  const m = Math.floor(totalSec / 60);
  const s = totalSec % 60;
  return `${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} o`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} Ko`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} Mo`;
}

export const ChatView: React.FC<ChatViewProps> = ({
  conversation,
  messages,
  authToken,
  isOnline,
  onBack,
  onOpenVerify,
  onUpdateTtl,
  onRotateKeyEpoch,
  onSendText,
  onSendMedia,
  onMarkRead,
  onDestroyInstantMessage,
}) => {
  const [draft, setDraft] = useState('');
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [nowMs, setNowMs] = useState(() => Date.now());
  const [rotatingKey, setRotatingKey] = useState(false);

  // Media menus & camera modals
  const [showPhotoMenu, setShowPhotoMenu] = useState(false);
  const [showVideoMenu, setShowVideoMenu] = useState(false);
  const [cameraMode, setCameraMode] = useState<'photo' | 'video' | null>(null);
  const [cameraError, setCameraError] = useState<string | null>(null);
  const [recordingVideo, setRecordingVideo] = useState(false);

  // Voice recording state
  const [recordingAudio, setRecordingAudio] = useState(false);
  const [audioElapsedMs, setAudioElapsedMs] = useState(0);
  const [recordedAudio, setRecordedAudio] = useState<{
    bytes: Uint8Array;
    mimeType: string;
    url: string;
    durationMs: number;
  } | null>(null);

  // Decrypted media blob URL cache
  const [mediaUrls, setMediaUrls] = useState<Record<string, string>>({});
  const [loadingMediaIds, setLoadingMediaIds] = useState<Record<string, boolean>>({});
  const [revealedInstantIds, setRevealedInstantIds] = useState<Record<string, boolean>>({});

  const endRef = useRef<HTMLDivElement | null>(null);
  const photoInputRef = useRef<HTMLInputElement | null>(null);
  const videoInputRef = useRef<HTMLInputElement | null>(null);
  const docInputRef = useRef<HTMLInputElement | null>(null);

  const audioRecorderRef = useRef<MediaRecorder | null>(null);
  const audioChunksRef = useRef<Blob[]>([]);
  const audioStartRef = useRef<number>(0);

  const cameraVideoRef = useRef<HTMLVideoElement | null>(null);
  const cameraStreamRef = useRef<MediaStream | null>(null);
  const videoRecorderRef = useRef<MediaRecorder | null>(null);
  const videoChunksRef = useRef<Blob[]>([]);

  // Live 1-second tick for ephemeral countdowns
  useEffect(() => {
    const id = setInterval(() => setNowMs(Date.now()), 500);
    return () => clearInterval(id);
  }, []);

  // Scroll to bottom when new messages arrive
  useEffect(() => {
    endRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages.length]);

  // Automatically mark non-instant incoming messages as read when conversation is visible
  useEffect(() => {
    if (!isOnline || conversation.status !== 'active') return;
    for (const m of messages) {
      if (!m.isMine && m.status !== 'read' && m.status !== 'expired' && m.ephemeralTtlMs > 0) {
        void onMarkRead(m.messageId);
      }
    }
  }, [messages, isOnline, conversation.status, onMarkRead]);

  // Audio recording timer
  useEffect(() => {
    if (!recordingAudio) return;
    const t = setInterval(() => {
      setAudioElapsedMs(Date.now() - audioStartRef.current);
    }, 200);
    return () => clearInterval(t);
  }, [recordingAudio]);

  // Clean up object URLs on unmount
  useEffect(() => {
    return () => {
      if (recordedAudio?.url) URL.revokeObjectURL(recordedAudio.url);
    };
  }, [recordedAudio]);

  const isVerified = conversation.verifiedFingerprint === conversation.peer.fingerprint;
  const isRevoked = conversation.status === 'revoked';

  const ensureMediaDecrypted = async (msg: DecryptedMessage) => {
    const media = msg.payload.media;
    if (!media || mediaUrls[msg.messageId] || loadingMediaIds[msg.messageId]) return;
    setLoadingMediaIds((prev) => ({ ...prev, [msg.messageId]: true }));
    try {
      const encBytes = await downloadEncryptedBlobApi(authToken, media.fileId);
      const plainBytes = await decryptFileBytes(encBytes, media.fileKeyB64, media.fileIvB64);
      const blob = new Blob([plainBytes.buffer.slice(0) as ArrayBuffer], { type: media.mimeType });
      const url = URL.createObjectURL(blob);
      setMediaUrls((prev) => ({ ...prev, [msg.messageId]: url }));
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Impossible de déchiffrer le média.');
    } finally {
      setLoadingMediaIds((prev) => ({ ...prev, [msg.messageId]: false }));
    }
  };

  // Auto-fetch encrypted audio/images/videos for non-instant messages
  useEffect(() => {
    for (const m of messages) {
      if (
        m.payload.media &&
        m.ephemeralTtlMs > 0 &&
        !mediaUrls[m.messageId] &&
        !loadingMediaIds[m.messageId] &&
        (m.messageType === 'image' || m.messageType === 'audio' || m.messageType === 'video')
      ) {
        void ensureMediaDecrypted(m);
      }
    }
  }, [messages]);

  const handleSendTextSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const trimmed = draft.trim();
    if (!trimmed || sending || isRevoked) return;
    setError(null);
    setSending(true);
    try {
      await onSendText(trimmed, conversation.ephemeralTtlMs);
      setDraft('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Échec de l’envoi chiffré.');
    } finally {
      setSending(false);
    }
  };

  // Voice recording handlers
  const startAudioRecording = async () => {
    setError(null);
    if (!navigator.mediaDevices?.getUserMedia || typeof MediaRecorder === 'undefined') {
      setError('Enregistrement audio non supporté par ce navigateur.');
      return;
    }
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      const mimeType = MediaRecorder.isTypeSupported('audio/webm')
        ? 'audio/webm'
        : 'audio/mp4';
      const recorder = new MediaRecorder(stream, mimeType ? { mimeType } : undefined);
      audioChunksRef.current = [];
      recorder.ondataavailable = (ev) => {
        if (ev.data.size > 0) audioChunksRef.current.push(ev.data);
      };
      recorder.onstop = async () => {
        stream.getTracks().forEach((t) => t.stop());
        const blob = new Blob(audioChunksRef.current, { type: recorder.mimeType || 'audio/webm' });
        const bytes = new Uint8Array(await blob.arrayBuffer());
        const url = URL.createObjectURL(blob);
        setRecordedAudio({
          bytes,
          mimeType: blob.type || 'audio/webm',
          url,
          durationMs: Date.now() - audioStartRef.current,
        });
      };
      audioStartRef.current = Date.now();
      setAudioElapsedMs(0);
      audioRecorderRef.current = recorder;
      recorder.start();
      setRecordingAudio(true);
    } catch {
      setError('Accès au microphone refusé.');
    }
  };

  const stopAudioRecording = () => {
    if (audioRecorderRef.current && audioRecorderRef.current.state !== 'inactive') {
      audioRecorderRef.current.stop();
    }
    setRecordingAudio(false);
  };

  const sendRecordedAudio = async () => {
    if (!recordedAudio || sending) return;
    setSending(true);
    setError(null);
    try {
      await onSendMedia({
        fileBytes: recordedAudio.bytes,
        mimeType: recordedAudio.mimeType,
        fileName: `vocal-${Date.now()}.webm`,
        messageType: 'audio',
        ttl: conversation.ephemeralTtlMs,
        durationMs: recordedAudio.durationMs,
      });
      URL.revokeObjectURL(recordedAudio.url);
      setRecordedAudio(null);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Erreur lors de l’envoi vocal.');
    } finally {
      setSending(false);
    }
  };

  // File picker upload
  const handleFileSelected = async (
    e: React.ChangeEvent<HTMLInputElement>,
    messageType: Exclude<MessageType, 'text'>
  ) => {
    const file = e.target.files?.[0];
    e.target.value = '';
    if (!file) return;
    if (file.size > 20 * 1024 * 1024) {
      setError('Taille maximale par fichier chiffré : 20 Mo.');
      return;
    }
    setSending(true);
    setError(null);
    try {
      const bytes = new Uint8Array(await file.arrayBuffer());
      await onSendMedia({
        fileBytes: bytes,
        mimeType: file.type || 'application/octet-stream',
        fileName: file.name,
        messageType,
        ttl: conversation.ephemeralTtlMs,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Échec du chiffrement du fichier.');
    } finally {
      setSending(false);
    }
  };

  // Camera capture for photo/video
  const openCamera = async (mode: 'photo' | 'video') => {
    setShowPhotoMenu(false);
    setShowVideoMenu(false);
    setCameraError(null);
    setCameraMode(mode);
    try {
      const stream = await navigator.mediaDevices.getUserMedia({
        video: { facingMode: 'environment' },
        audio: mode === 'video',
      });
      cameraStreamRef.current = stream;
      if (cameraVideoRef.current) {
        cameraVideoRef.current.srcObject = stream;
        await cameraVideoRef.current.play();
      }
    } catch {
      setCameraError('Impossible d’accéder à la caméra sur cet appareil.');
    }
  };

  const closeCamera = () => {
    if (videoRecorderRef.current && videoRecorderRef.current.state !== 'inactive') {
      videoRecorderRef.current.stop();
    }
    cameraStreamRef.current?.getTracks().forEach((t) => t.stop());
    cameraStreamRef.current = null;
    setRecordingVideo(false);
    setCameraMode(null);
  };

  const snapPhoto = async () => {
    const video = cameraVideoRef.current;
    if (!video) return;
    const canvas = document.createElement('canvas');
    canvas.width = video.videoWidth || 640;
    canvas.height = video.videoHeight || 480;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
    const blob = await new Promise<Blob | null>((resolve) =>
      canvas.toBlob(resolve, 'image/jpeg', 0.88)
    );
    closeCamera();
    if (!blob) return;
    setSending(true);
    try {
      const bytes = new Uint8Array(await blob.arrayBuffer());
      await onSendMedia({
        fileBytes: bytes,
        mimeType: 'image/jpeg',
        fileName: `photo-${Date.now()}.jpg`,
        messageType: 'image',
        ttl: conversation.ephemeralTtlMs,
      });
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Échec de l’envoi photo.');
    } finally {
      setSending(false);
    }
  };

  const toggleVideoCapture = () => {
    if (recordingVideo) {
      videoRecorderRef.current?.stop();
      setRecordingVideo(false);
      return;
    }
    const stream = cameraStreamRef.current;
    if (!stream) return;
    videoChunksRef.current = [];
    const recorder = new MediaRecorder(stream);
    recorder.ondataavailable = (ev) => {
      if (ev.data.size > 0) videoChunksRef.current.push(ev.data);
    };
    recorder.onstop = async () => {
      const blob = new Blob(videoChunksRef.current, { type: recorder.mimeType || 'video/webm' });
      closeCamera();
      setSending(true);
      try {
        const bytes = new Uint8Array(await blob.arrayBuffer());
        await onSendMedia({
          fileBytes: bytes,
          mimeType: blob.type || 'video/webm',
          fileName: `video-${Date.now()}.webm`,
          messageType: 'video',
          ttl: conversation.ephemeralTtlMs,
        });
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Échec de l’envoi vidéo.');
      } finally {
        setSending(false);
      }
    };
    videoRecorderRef.current = recorder;
    recorder.start();
    setRecordingVideo(true);
  };

  const handleRevealInstant = async (msg: DecryptedMessage) => {
    setRevealedInstantIds((prev) => ({ ...prev, [msg.messageId]: true }));
    if (msg.payload.media) {
      await ensureMediaDecrypted(msg);
    }
    await onMarkRead(msg.messageId);
  };

  const handleRotateKeys = async () => {
    setRotatingKey(true);
    try {
      await onRotateKeyEpoch();
    } finally {
      setRotatingKey(false);
    }
  };

  return (
    <div className="flex flex-col h-full bg-slate-50 dark:bg-[#050811] text-slate-950 dark:text-slate-50">
      {/* Chat Header */}
      <header className="shrink-0 px-3 sm:px-4 py-2.5 border-b border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          {onBack && (
            <button
              type="button"
              onClick={onBack}
              aria-label="Retour aux conversations"
              className="md:hidden min-h-[44px] min-w-[44px] rounded-xl flex items-center justify-center hover:bg-slate-100 dark:hover:bg-slate-800 shrink-0"
            >
              <ArrowLeft className="w-5 h-5" />
            </button>
          )}
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <h2 className="font-display text-base sm:text-lg font-bold truncate">
                {conversation.peer.pseudonym}
              </h2>
              {conversation.peerOnline && !isRevoked && (
                <span
                  className="w-2 h-2 rounded-full bg-emerald-500 shrink-0"
                  title="Correspondant connecté"
                />
              )}
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400 truncate">
              {isRevoked
                ? 'Association révoquée'
                : conversation.peerOnline
                ? 'En ligne'
                : 'Hors ligne'}{' '}
              · Clé #{conversation.keyEpoch}
            </p>
          </div>
        </div>

        <div className="flex items-center gap-1.5 sm:gap-2 shrink-0">
          <label htmlFor="chat-ttl-select" className="sr-only">
            Durée des messages éphémères
          </label>
          <select
            id="chat-ttl-select"
            disabled={isRevoked}
            value={conversation.ephemeralTtlMs}
            onChange={(e) => void onUpdateTtl(Number(e.target.value) as EphemeralDurationMs)}
            className="min-h-[40px] px-2 sm:px-2.5 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#050811] text-xs font-medium"
          >
            {EPHEMERAL_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.shortLabel}
              </option>
            ))}
          </select>

          <button
            type="button"
            onClick={handleRotateKeys}
            disabled={rotatingKey || isRevoked}
            title="Renouveler l’époque de clé de session"
            aria-label="Renouveler les clés de conversation"
            className="min-h-[40px] min-w-[40px] px-2.5 rounded-xl border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 flex items-center justify-center gap-1.5 text-xs font-medium disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${rotatingKey ? 'animate-spin' : ''}`} />
            <span className="hidden lg:inline">Renouveler clé</span>
          </button>

          <button
            type="button"
            onClick={onOpenVerify}
            aria-label="Vérifier l’identité du correspondant"
            className={`min-h-[40px] min-w-[40px] px-2.5 sm:px-3 rounded-xl border text-xs font-medium flex items-center justify-center gap-1.5 whitespace-nowrap ${
              isVerified
                ? 'border-emerald-300 dark:border-emerald-900/60 text-emerald-700 dark:text-emerald-400'
                : 'border-amber-300 dark:border-amber-900/60 text-amber-700 dark:text-amber-400'
            }`}
          >
            {isVerified ? (
              <ShieldCheck className="w-4 h-4" />
            ) : (
              <ShieldAlert className="w-4 h-4" />
            )}
            <span className="hidden sm:inline">{isVerified ? 'Vérifié' : 'Vérifier'}</span>
          </button>
        </div>
      </header>

      {/* Message Stream */}
      <div className="flex-1 overflow-y-auto px-4 py-5 space-y-3" data-testid="chat-messages">
        {messages.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-center max-w-sm mx-auto space-y-3 py-12">
            <KeyRound className="w-8 h-8 text-blue-600 dark:text-blue-400 opacity-80" />
            <p className="font-display font-semibold text-base">
              Canal privé chiffré de bout en bout
            </p>
            <p className="text-xs text-slate-500 dark:text-slate-400 leading-relaxed">
              Seuls {conversation.peer.pseudonym} et vous possédez les clés pour déchiffrer cette
              conversation. Les messages lus disparaissent automatiquement selon la durée choisie.
            </p>
          </div>
        ) : (
          messages.map((msg) => {
            const isInstantHidden =
              !msg.isMine && msg.ephemeralTtlMs === 0 && !revealedInstantIds[msg.messageId];
            const remainingMs =
              typeof msg.expiresAt === 'number'
                ? Math.min(msg.ephemeralTtlMs, Math.max(0, msg.expiresAt - nowMs))
                : null;
            const mediaUrl = mediaUrls[msg.messageId];
            const media = msg.payload.media;

            return (
              <div
                key={msg.messageId}
                data-testid="chat-message-item"
                className={`flex ${msg.isMine ? 'justify-end' : 'justify-start'}`}
              >
                <div
                  className={`max-w-[85%] sm:max-w-[70%] rounded-2xl px-4 py-3 space-y-2 border ${
                    msg.isMine
                      ? 'bg-[#0A1433] dark:bg-blue-700 text-white border-[#0A1433] dark:border-blue-600'
                      : 'bg-white dark:bg-[#0A1128] text-slate-900 dark:text-slate-100 border-slate-200 dark:border-slate-800'
                  }`}
                >
                  {isInstantHidden ? (
                    <div className="space-y-2">
                      <p className="text-xs opacity-80">
                        Message éphémère à lecture unique ({msg.messageType})
                      </p>
                      <button
                        type="button"
                        onClick={() => void handleRevealInstant(msg)}
                        className="min-h-[38px] px-3 rounded-xl bg-blue-600 text-white text-xs font-medium flex items-center gap-1.5 hover:bg-blue-500"
                      >
                        <Eye className="w-3.5 h-3.5" />
                        Afficher le message éphémère
                      </button>
                    </div>
                  ) : (
                    <>
                      {msg.decryptionError ? (
                        <p className="text-xs text-red-400">{msg.decryptionError}</p>
                      ) : (
                        <>
                          {msg.payload.text && (
                            <p className="text-sm leading-relaxed whitespace-pre-wrap break-words">
                              {msg.payload.text}
                            </p>
                          )}

                          {media && msg.messageType === 'audio' && (
                            <div className="space-y-1">
                              {mediaUrl ? (
                                <audio controls src={mediaUrl} className="w-56 sm:w-64 h-10" />
                              ) : (
                                <p className="text-xs opacity-75">Déchiffrement de l’audio…</p>
                              )}
                            </div>
                          )}

                          {media && msg.messageType === 'image' && (
                            <div className="space-y-1.5">
                              {mediaUrl ? (
                                <img
                                  src={mediaUrl}
                                  alt={media.fileName}
                                  className="rounded-xl max-h-72 w-auto object-contain bg-black/20"
                                />
                              ) : (
                                <p className="text-xs opacity-75">Déchiffrement de l’image…</p>
                              )}
                            </div>
                          )}

                          {media && msg.messageType === 'video' && (
                            <div className="space-y-1.5">
                              {mediaUrl ? (
                                <video
                                  controls
                                  src={mediaUrl}
                                  className="rounded-xl max-h-72 w-full bg-black"
                                />
                              ) : (
                                <p className="text-xs opacity-75">Déchiffrement de la vidéo…</p>
                              )}
                            </div>
                          )}

                          {media && msg.messageType === 'document' && (
                            <div className="flex items-center justify-between gap-3 p-2.5 rounded-xl bg-black/10 dark:bg-white/5">
                              <div className="flex items-center gap-2 min-w-0">
                                <FileText className="w-4 h-4 shrink-0" />
                                <div className="min-w-0">
                                  <p className="text-xs font-medium truncate">{media.fileName}</p>
                                  <p className="text-[11px] opacity-70">
                                    {formatBytes(media.fileSize)}
                                  </p>
                                </div>
                              </div>
                              <button
                                type="button"
                                onClick={async () => {
                                  if (!mediaUrl) {
                                    await ensureMediaDecrypted(msg);
                                    return;
                                  }
                                  const a = document.createElement('a');
                                  a.href = mediaUrl;
                                  a.download = media.fileName;
                                  a.click();
                                }}
                                className="min-h-[36px] px-2.5 rounded-lg bg-blue-600 text-white text-xs font-medium flex items-center gap-1 shrink-0"
                              >
                                <Download className="w-3.5 h-3.5" />
                                {mediaUrl ? 'Télécharger' : 'Déchiffrer'}
                              </button>
                            </div>
                          )}
                        </>
                      )}

                      {revealedInstantIds[msg.messageId] && (
                        <button
                          type="button"
                          onClick={() => onDestroyInstantMessage(msg.messageId)}
                          className="text-xs text-red-400 hover:underline flex items-center gap-1"
                        >
                          <Trash2 className="w-3 h-3" />
                          Fermer et détruire maintenant
                        </button>
                      )}
                    </>
                  )}

                  {/* Footer: Timestamp, ephemeral countdown, delivery/read ticks */}
                  <div
                    className={`flex items-center justify-end gap-2 text-[11px] ${
                      msg.isMine
                        ? 'text-blue-100/80'
                        : 'text-slate-500 dark:text-slate-400'
                    }`}
                  >
                    {remainingMs !== null && msg.status === 'read' && (
                      <span className="font-mono flex items-center gap-1 text-amber-400">
                        <Clock className="w-3 h-3" />
                        {formatDurationClock(remainingMs)}
                      </span>
                    )}
                    <span className="font-mono">
                      {new Date(msg.createdAt).toLocaleTimeString('fr-FR', {
                        hour: '2-digit',
                        minute: '2-digit',
                      })}
                    </span>
                    {msg.isMine && (
                      <span className="flex items-center gap-0.5" title={msg.status}>
                        {msg.status === 'sent' && (
                          <>
                            <Check className="w-3.5 h-3.5" />
                            <span>Envoyé</span>
                          </>
                        )}
                        {msg.status === 'delivered' && (
                          <>
                            <CheckCheck className="w-3.5 h-3.5" />
                            <span>Reçu</span>
                          </>
                        )}
                        {msg.status === 'read' && (
                          <>
                            <CheckCheck className="w-3.5 h-3.5 text-sky-300" />
                            <span>Lu</span>
                          </>
                        )}
                      </span>
                    )}
                  </div>
                </div>
              </div>
            );
          })
        )}
        <div ref={endRef} />
      </div>

      {/* Camera capture modal */}
      {cameraMode && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-4">
          <div className="w-full max-w-md rounded-2xl bg-[#0A1128] border border-slate-800 p-4 space-y-4 text-white">
            <div className="flex items-center justify-between">
              <h3 className="font-display font-semibold">
                {cameraMode === 'photo' ? 'Prendre une photo chiffrée' : 'Enregistrer une vidéo'}
              </h3>
              <button
                type="button"
                onClick={closeCamera}
                aria-label="Fermer la caméra"
                className="min-h-[40px] min-w-[40px] rounded-xl flex items-center justify-center hover:bg-slate-800"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
            {cameraError ? (
              <p className="text-sm text-red-400">{cameraError}</p>
            ) : (
              <>
                <video
                  ref={cameraVideoRef}
                  playsInline
                  muted
                  className="w-full rounded-xl bg-black aspect-video object-cover"
                />
                <div className="flex justify-center">
                  {cameraMode === 'photo' ? (
                    <button
                      type="button"
                      onClick={() => void snapPhoto()}
                      className="min-h-[48px] px-6 rounded-xl bg-blue-600 font-medium hover:bg-blue-500"
                    >
                      Capturer et chiffrer
                    </button>
                  ) : (
                    <button
                      type="button"
                      onClick={toggleVideoCapture}
                      className={`min-h-[48px] px-6 rounded-xl font-medium ${
                        recordingVideo
                          ? 'bg-red-600 hover:bg-red-500'
                          : 'bg-blue-600 hover:bg-blue-500'
                      }`}
                    >
                      {recordingVideo ? 'Arrêter et chiffrer' : 'Démarrer l’enregistrement'}
                    </button>
                  )}
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* Error & Offline bar */}
      {error && (
        <div
          role="alert"
          className="mx-4 mb-2 px-4 py-2.5 rounded-xl bg-red-50 dark:bg-red-950/50 border border-red-200 dark:border-red-900 text-xs text-red-700 dark:text-red-300 flex items-center justify-between"
        >
          <span>{error}</span>
          <button type="button" onClick={() => setError(null)} aria-label="Fermer l’alerte">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {!isOnline && (
        <div className="mx-4 mb-2 px-4 py-2 rounded-xl bg-amber-50 dark:bg-amber-950/40 border border-amber-200 dark:border-amber-900 text-xs text-amber-800 dark:text-amber-200">
          Connexion temps réel interrompue. Aucune donnée en clair n’est exposée ; reconnexion automatique en cours.
        </div>
      )}

      {/* Composer */}
      <footer className="shrink-0 p-3 sm:p-4 border-t border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128]">
        {isRevoked ? (
          <p className="text-center text-xs text-red-600 dark:text-red-400 py-2">
            Cette association a été révoquée. Aucun nouveau message ne peut être envoyé.
          </p>
        ) : recordedAudio ? (
          <div className="flex flex-wrap items-center gap-3">
            <audio controls src={recordedAudio.url} className="flex-1 min-w-[200px] h-10" />
            <button
              type="button"
              onClick={() => {
                URL.revokeObjectURL(recordedAudio.url);
                setRecordedAudio(null);
              }}
              aria-label="Supprimer l’enregistrement vocal"
              className="min-h-[44px] min-w-[44px] px-3 rounded-xl border border-red-300 dark:border-red-900 text-red-600 dark:text-red-400 flex items-center justify-center"
            >
              <Trash2 className="w-4 h-4" />
            </button>
            <button
              type="button"
              disabled={sending}
              onClick={() => void sendRecordedAudio()}
              className="min-h-[44px] px-4 rounded-xl bg-[#0A1433] dark:bg-blue-600 text-white text-sm font-medium flex items-center gap-2"
            >
              <Send className="w-4 h-4" />
              Envoyer le vocal
            </button>
          </div>
        ) : recordingAudio ? (
          <div className="flex items-center justify-between gap-4 px-2">
            <div className="flex items-center gap-2.5 text-sm font-medium text-red-600 dark:text-red-400">
              <span className="w-2.5 h-2.5 rounded-full bg-red-600 animate-pulse" />
              <span>Enregistrement vocal…</span>
              <span className="font-mono">{formatDurationClock(audioElapsedMs)}</span>
            </div>
            <button
              type="button"
              onClick={stopAudioRecording}
              className="min-h-[44px] px-4 rounded-xl bg-red-600 text-white text-sm font-medium flex items-center gap-2"
            >
              <Square className="w-4 h-4" />
              Arrêter et écouter
            </button>
          </div>
        ) : (
          <form onSubmit={handleSendTextSubmit} className="flex flex-col sm:flex-row sm:items-center gap-2">
            {/* Hidden file inputs */}
            <input
              ref={photoInputRef}
              type="file"
              accept="image/*"
              onChange={(e) => void handleFileSelected(e, 'image')}
              className="hidden"
            />
            <input
              ref={videoInputRef}
              type="file"
              accept="video/*"
              onChange={(e) => void handleFileSelected(e, 'video')}
              className="hidden"
            />
            <input
              ref={docInputRef}
              type="file"
              onChange={(e) => void handleFileSelected(e, 'document')}
              className="hidden"
            />

            <div className="flex items-center gap-2 sm:order-1">
              {/* Photo menu */}
              <div className="relative">
                <button
                  type="button"
                  aria-label="Envoyer une photo"
                  onClick={() => {
                    setShowPhotoMenu((v) => !v);
                    setShowVideoMenu(false);
                  }}
                  className="min-h-[44px] min-w-[44px] rounded-xl border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 flex items-center justify-center"
                >
                  <ImageIcon className="w-4 h-4" />
                </button>
                {showPhotoMenu && (
                  <div className="absolute bottom-14 left-0 z-30 w-52 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-[#0A1128] shadow-xl p-1.5 space-y-1">
                    <button
                      type="button"
                      onClick={() => void openCamera('photo')}
                      className="w-full min-h-[40px] px-3 rounded-lg text-left text-xs font-medium flex items-center gap-2 hover:bg-slate-100 dark:hover:bg-slate-800"
                    >
                      <Camera className="w-4 h-4" />
                      Prendre une photo
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setShowPhotoMenu(false);
                        photoInputRef.current?.click();
                      }}
                      className="w-full min-h-[40px] px-3 rounded-lg text-left text-xs font-medium flex items-center gap-2 hover:bg-slate-100 dark:hover:bg-slate-800"
                    >
                      <ImageIcon className="w-4 h-4" />
                      Choisir dans la galerie
                    </button>
                  </div>
                )}
              </div>

              {/* Video menu */}
              <div className="relative">
                <button
                  type="button"
                  aria-label="Envoyer une vidéo"
                  onClick={() => {
                    setShowVideoMenu((v) => !v);
                    setShowPhotoMenu(false);
                  }}
                  className="min-h-[44px] min-w-[44px] rounded-xl border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 flex items-center justify-center"
                >
                  <Video className="w-4 h-4" />
                </button>
                {showVideoMenu && (
                  <div className="absolute bottom-14 left-0 z-30 w-52 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-[#0A1128] shadow-xl p-1.5 space-y-1">
                    <button
                      type="button"
                      onClick={() => void openCamera('video')}
                      className="w-full min-h-[40px] px-3 rounded-lg text-left text-xs font-medium flex items-center gap-2 hover:bg-slate-100 dark:hover:bg-slate-800"
                    >
                      <Video className="w-4 h-4" />
                      Enregistrer une vidéo
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setShowVideoMenu(false);
                        videoInputRef.current?.click();
                      }}
                      className="w-full min-h-[40px] px-3 rounded-lg text-left text-xs font-medium flex items-center gap-2 hover:bg-slate-100 dark:hover:bg-slate-800"
                    >
                      <Video className="w-4 h-4" />
                      Choisir une vidéo
                    </button>
                  </div>
                )}
              </div>

              {/* Document picker */}
              <button
                type="button"
                aria-label="Envoyer un document"
                onClick={() => docInputRef.current?.click()}
                className="min-h-[44px] min-w-[44px] rounded-xl border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 flex items-center justify-center"
              >
                <Paperclip className="w-4 h-4" />
              </button>

              {/* Voice button */}
              <button
                type="button"
                aria-label="Enregistrer un message vocal"
                onClick={() => void startAudioRecording()}
                className="min-h-[44px] min-w-[44px] rounded-xl border border-slate-200 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 flex items-center justify-center"
              >
                <Mic className="w-4 h-4" />
              </button>
            </div>

            <div className="flex items-center gap-2 flex-1 min-w-0 sm:order-2">
              <input
                type="text"
                value={draft}
                onChange={(e) => setDraft(e.target.value)}
                placeholder="Message chiffré de bout en bout…"
                aria-label="Message chiffré"
                className="flex-1 min-w-0 min-h-[44px] px-4 rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#050811] text-sm focus:outline-none focus:ring-2 focus:ring-blue-600"
              />

              <button
                type="submit"
                disabled={!draft.trim() || sending}
                aria-label="Envoyer le message"
                className="min-h-[44px] px-4 rounded-xl bg-[#0A1433] dark:bg-blue-600 text-white text-sm font-medium hover:bg-[#112254] dark:hover:bg-blue-500 disabled:opacity-40 flex items-center gap-1.5 whitespace-nowrap shrink-0"
              >
                <Send className="w-4 h-4" />
                <span className="hidden sm:inline">Envoyer</span>
              </button>
            </div>
          </form>
        )}
      </footer>
    </div>
  );
};
