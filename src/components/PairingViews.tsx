import React, { useEffect, useRef, useState } from 'react';
import QRCode from 'qrcode';
import jsQR from 'jsqr';
import {
  ArrowLeft,
  Camera,
  Check,
  Copy,
  QrCode,
  RefreshCw,
  Share2,
  ShieldAlert,
  ShieldCheck,
  Upload,
} from 'lucide-react';
import { computeJointSafetyNumber, toPublicIdentity } from '../crypto/emeshCrypto';
import type { PeerConversation, UnlockedIdentity } from '../types';

function formatCountdown(ms: number): string {
  const totalSec = Math.max(0, Math.floor(ms / 1000));
  const min = Math.floor(totalSec / 60);
  const sec = totalSec % 60;
  return `${String(min).padStart(2, '0')}:${String(sec).padStart(2, '0')}`;
}

interface GenerateCodeViewProps {
  onCreateCode: () => Promise<{ code: string; expiresAt: number }>;
  onBack: () => void;
}

export const GenerateCodeView: React.FC<GenerateCodeViewProps> = ({ onCreateCode, onBack }) => {
  const [code, setCode] = useState<string>('');
  const [expiresAt, setExpiresAt] = useState<number>(0);
  const [remainingMs, setRemainingMs] = useState<number>(0);
  const [qrDataUrl, setQrDataUrl] = useState<string>('');
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState<boolean>(false);

  const generate = async () => {
    setLoading(true);
    setError(null);
    setCopied(false);
    try {
      const res = await onCreateCode();
      setCode(res.code);
      setExpiresAt(res.expiresAt);
      setRemainingMs(Math.max(0, res.expiresAt - Date.now()));
      const qrPayload = `emesh://pair?code=${encodeURIComponent(res.code)}`;
      const url = await QRCode.toDataURL(qrPayload, {
        width: 240,
        margin: 2,
        color: {
          dark: '#050811',
          light: '#FFFFFF',
        },
      });
      setQrDataUrl(url);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Erreur lors de la génération du code.');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void generate();
  }, []);

  useEffect(() => {
    if (!expiresAt) return;
    const timer = setInterval(() => {
      setRemainingMs(Math.max(0, expiresAt - Date.now()));
    }, 500);
    return () => clearInterval(timer);
  }, [expiresAt]);

  const handleCopy = async () => {
    if (!code) return;
    try {
      await navigator.clipboard.writeText(code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setError('Copie automatique bloquée par le navigateur.');
    }
  };

  const handleShare = async () => {
    if (!code) return;
    if (navigator.share) {
      try {
        await navigator.share({
          title: 'Code de connexion eMesh',
          text: `Rejoins ma conversation privée eMesh avec ce code unique (valide 10 min) : ${code}`,
        });
        return;
      } catch {
        // Fallback to copy
      }
    }
    await handleCopy();
  };

  const isExpired = expiresAt > 0 && remainingMs <= 0;

  return (
    <div className="max-w-2xl mx-auto p-4 sm:p-8 space-y-6">
      <div className="flex items-center justify-between gap-4">
        <button
          type="button"
          onClick={onBack}
          className="min-h-[44px] px-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] text-sm font-medium flex items-center gap-2 hover:bg-slate-100 dark:hover:bg-slate-800/70 transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
          Retour
        </button>
        <span className="text-xs font-medium text-slate-500 dark:text-slate-400">
          Usage unique · Expiration 10 min
        </span>
      </div>

      <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] p-6 sm:p-8 space-y-6">
        <div className="space-y-1.5">
          <h1 className="font-display text-2xl font-bold text-slate-950 dark:text-white">
            Connecter un correspondant
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-300">
            Transmettez ce code unique ou faites scanner ce QR code à votre correspondant. Dès qu’il
            le valide, le code est détruit et la conversation privée s’ouvre.
          </p>
        </div>

        {error && (
          <div
            role="alert"
            className="p-4 rounded-xl border border-red-300 dark:border-red-900/60 bg-red-50 dark:bg-red-950/30 text-sm text-red-700 dark:text-red-300"
          >
            {error}
          </div>
        )}

        {loading ? (
          <div className="py-12 text-center text-sm text-slate-500 dark:text-slate-400">
            Génération cryptographique du code unique…
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-6 items-center">
            <div className="flex flex-col items-center justify-center p-5 rounded-2xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#050811]">
              {qrDataUrl && !isExpired ? (
                <img
                  src={qrDataUrl}
                  alt="QR code d’association eMesh"
                  className="w-48 h-48 rounded-lg bg-white p-2"
                />
              ) : (
                <div className="w-48 h-48 flex items-center justify-center text-sm text-slate-500 text-center">
                  Code expiré. Générez un nouveau code.
                </div>
              )}
            </div>

            <div className="space-y-5">
              <div className="space-y-1">
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  Code unique (10 caractères)
                </p>
                <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#050811] text-center">
                  <span
                    data-testid="pairing-code-value"
                    className={`font-mono text-2xl sm:text-3xl font-bold tracking-wider ${
                      isExpired ? 'line-through text-slate-400' : 'text-slate-950 dark:text-white'
                    }`}
                  >
                    {code}
                  </span>
                </div>
              </div>

              <div className="flex items-center justify-between text-sm">
                <span className="text-slate-600 dark:text-slate-300">Validité restante</span>
                <span
                  className={`font-mono font-semibold ${
                    isExpired ? 'text-red-600 dark:text-red-400' : 'text-blue-700 dark:text-blue-400'
                  }`}
                >
                  {isExpired ? 'Expiré' : formatCountdown(remainingMs)}
                </span>
              </div>

              <div className="flex flex-wrap gap-3">
                <button
                  type="button"
                  onClick={handleCopy}
                  disabled={isExpired}
                  className="flex-1 min-h-[44px] px-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#050811] text-sm font-medium flex items-center justify-center gap-2 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-50 whitespace-nowrap"
                >
                  {copied ? <Check className="w-4 h-4 text-emerald-500" /> : <Copy className="w-4 h-4" />}
                  {copied ? 'Copié' : 'Copier'}
                </button>
                <button
                  type="button"
                  onClick={handleShare}
                  disabled={isExpired}
                  className="flex-1 min-h-[44px] px-4 rounded-xl bg-[#0A1433] dark:bg-blue-600 text-white text-sm font-medium flex items-center justify-center gap-2 hover:bg-[#112254] dark:hover:bg-blue-500 disabled:opacity-50 whitespace-nowrap"
                >
                  <Share2 className="w-4 h-4" />
                  Partager
                </button>
              </div>

              <button
                type="button"
                onClick={generate}
                className="w-full min-h-[44px] px-4 rounded-xl border border-slate-200 dark:border-slate-800 text-sm font-medium text-slate-700 dark:text-slate-300 flex items-center justify-center gap-2 hover:bg-slate-100 dark:hover:bg-slate-800/60"
              >
                <RefreshCw className="w-4 h-4" />
                Générer un nouveau code
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

interface JoinCodeViewProps {
  onRedeemCode: (code: string) => Promise<void>;
  onOpenScanner: () => void;
  onBack: () => void;
}

export const JoinCodeView: React.FC<JoinCodeViewProps> = ({
  onRedeemCode,
  onOpenScanner,
  onBack,
}) => {
  const [code, setCode] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    const cleaned = code.toUpperCase().replace(/[^A-Z0-9]/g, '');
    if (cleaned.length < 8) {
      setError('Veuillez entrer un code valide d’au moins 8 caractères.');
      return;
    }
    setBusy(true);
    try {
      await onRedeemCode(code);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Code invalide ou expiré.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="max-w-lg mx-auto p-4 sm:p-8 space-y-6">
      <button
        type="button"
        onClick={onBack}
        className="min-h-[44px] px-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] text-sm font-medium flex items-center gap-2 hover:bg-slate-100 dark:hover:bg-slate-800/70"
      >
        <ArrowLeft className="w-4 h-4" />
        Retour
      </button>

      <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] p-6 sm:p-8 space-y-6">
        <div className="space-y-1.5">
          <h1 className="font-display text-2xl font-bold text-slate-950 dark:text-white">
            Rejoindre avec un code
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-300">
            Saisissez le code unique transmis par votre correspondant pour établir l’association
            cryptographique exclusive.
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="join-code-input" className="block text-sm font-medium">
              Code de connexion (8+ caractères)
            </label>
            <input
              id="join-code-input"
              type="text"
              value={code}
              onChange={(e) => setCode(e.target.value.toUpperCase())}
              placeholder="XXXXX-XXXXX"
              autoFocus
              required
              className="w-full min-h-[52px] px-4 rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#050811] font-mono text-xl tracking-widest text-center uppercase focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>

          {error && (
            <div
              role="alert"
              className="p-3.5 rounded-xl border border-red-300 dark:border-red-900/60 bg-red-50 dark:bg-red-950/30 text-sm text-red-700 dark:text-red-300"
            >
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={busy}
            className="w-full min-h-[48px] px-5 rounded-xl bg-[#0A1433] dark:bg-blue-600 text-white font-medium hover:bg-[#112254] dark:hover:bg-blue-500 disabled:opacity-50 transition-colors"
          >
            {busy ? 'Vérification et association…' : 'Valider et associer'}
          </button>
        </form>

        <div className="pt-4 border-t border-slate-100 dark:border-slate-800">
          <button
            type="button"
            onClick={onOpenScanner}
            className="w-full min-h-[44px] px-4 rounded-xl border border-slate-200 dark:border-slate-700 text-sm font-medium flex items-center justify-center gap-2 hover:bg-slate-100 dark:hover:bg-slate-800/60"
          >
            <QrCode className="w-4 h-4" />
            Scanner un QR code à la place
          </button>
        </div>
      </div>
    </div>
  );
};

interface ScanQrViewProps {
  onRedeemCode: (code: string) => Promise<void>;
  onGoManualCode: () => void;
  onBack: () => void;
}

export const ScanQrView: React.FC<ScanQrViewProps> = ({
  onRedeemCode,
  onGoManualCode,
  onBack,
}) => {
  const videoRef = useRef<HTMLVideoElement | null>(null);
  const canvasRef = useRef<HTMLCanvasElement | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  const [cameraActive, setCameraActive] = useState(false);
  const [status, setStatus] = useState<string>('Démarrez la caméra ou importez une image QR.');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const extractPairingCode = (rawText: string): string => {
    try {
      if (rawText.startsWith('emesh://')) {
        const url = new URL(rawText);
        const c = url.searchParams.get('code');
        if (c) return c;
      }
    } catch {
      // fallback to raw
    }
    return rawText;
  };

  const handleDecoded = async (rawText: string) => {
    if (busy) return;
    setBusy(true);
    setError(null);
    const code = extractPairingCode(rawText);
    setStatus(`Code détecté (${code}). Association en cours…`);
    try {
      await onRedeemCode(code);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Échec de validation du QR code.');
      setBusy(false);
    }
  };

  useEffect(() => {
    let stream: MediaStream | null = null;
    let rafId = 0;
    let cancelled = false;

    const startCamera = async () => {
      if (!navigator.mediaDevices?.getUserMedia) {
        setStatus('Caméra indisponible sur ce navigateur. Utilisez l’import d’image QR ci-dessous.');
        return;
      }
      try {
        stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: 'environment' },
        });
        if (cancelled) {
          stream.getTracks().forEach((t) => t.stop());
          return;
        }
        if (videoRef.current) {
          videoRef.current.srcObject = stream;
          await videoRef.current.play();
          setCameraActive(true);
          setStatus('Pointez la caméra vers le QR code de votre correspondant.');
        }

        const tick = () => {
          if (cancelled) return;
          const video = videoRef.current;
          const canvas = canvasRef.current;
          if (video && canvas && video.readyState === video.HAVE_ENOUGH_DATA) {
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
            const ctx = canvas.getContext('2d');
            if (ctx) {
              ctx.drawImage(video, 0, 0, canvas.width, canvas.height);
              const imgData = ctx.getImageData(0, 0, canvas.width, canvas.height);
              const decoded = jsQR(imgData.data, imgData.width, imgData.height);
              if (decoded?.data) {
                void handleDecoded(decoded.data);
                return;
              }
            }
          }
          rafId = requestAnimationFrame(tick);
        };
        rafId = requestAnimationFrame(tick);
      } catch {
        setStatus(
          'Accès caméra refusé ou absent. Vous pouvez importer une image de QR code ou saisir le code.'
        );
      }
    };

    void startCamera();

    return () => {
      cancelled = true;
      if (rafId) cancelAnimationFrame(rafId);
      if (stream) stream.getTracks().forEach((t) => t.stop());
    };
  }, []);

  const handleImageUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setError(null);
    const img = new Image();
    const url = URL.createObjectURL(file);
    img.onload = () => {
      const canvas = document.createElement('canvas');
      canvas.width = img.width;
      canvas.height = img.height;
      const ctx = canvas.getContext('2d');
      if (ctx) {
        ctx.drawImage(img, 0, 0);
        const data = ctx.getImageData(0, 0, canvas.width, canvas.height);
        const decoded = jsQR(data.data, data.width, data.height);
        URL.revokeObjectURL(url);
        if (decoded?.data) {
          void handleDecoded(decoded.data);
        } else {
          setError('Aucun QR code détecté dans cette image.');
        }
      }
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      setError('Impossible de lire le fichier image.');
    };
    img.src = url;
  };

  return (
    <div className="max-w-lg mx-auto p-4 sm:p-8 space-y-6">
      <button
        type="button"
        onClick={onBack}
        className="min-h-[44px] px-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] text-sm font-medium flex items-center gap-2 hover:bg-slate-100 dark:hover:bg-slate-800/70"
      >
        <ArrowLeft className="w-4 h-4" />
        Retour
      </button>

      <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] p-6 sm:p-8 space-y-5">
        <div className="space-y-1.5">
          <h1 className="font-display text-2xl font-bold text-slate-950 dark:text-white">
            Scanner un QR code
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-300">{status}</p>
        </div>

        <div className="relative rounded-2xl overflow-hidden border border-slate-200 dark:border-slate-800 bg-slate-950 aspect-square max-h-72 mx-auto flex items-center justify-center">
          <video
            ref={videoRef}
            playsInline
            muted
            className={`w-full h-full object-cover ${cameraActive ? 'block' : 'hidden'}`}
          />
          {!cameraActive && (
            <div className="p-6 text-center space-y-2 text-slate-400">
              <Camera className="w-10 h-10 mx-auto opacity-60" />
              <p className="text-xs">Aperçu caméra en attente</p>
            </div>
          )}
          <canvas ref={canvasRef} className="hidden" />
        </div>

        {error && (
          <div
            role="alert"
            className="p-3.5 rounded-xl border border-red-300 dark:border-red-900/60 bg-red-50 dark:bg-red-950/30 text-sm text-red-700 dark:text-red-300"
          >
            {error}
          </div>
        )}

        <div className="flex flex-col sm:flex-row gap-3">
          <input
            ref={fileInputRef}
            type="file"
            accept="image/*"
            onChange={handleImageUpload}
            className="hidden"
          />
          <button
            type="button"
            onClick={() => fileInputRef.current?.click()}
            className="flex-1 min-h-[44px] px-4 rounded-xl border border-slate-200 dark:border-slate-700 text-sm font-medium flex items-center justify-center gap-2 hover:bg-slate-100 dark:hover:bg-slate-800/60"
          >
            <Upload className="w-4 h-4" />
            Importer une image QR
          </button>
          <button
            type="button"
            onClick={onGoManualCode}
            className="flex-1 min-h-[44px] px-4 rounded-xl bg-[#0A1433] dark:bg-blue-600 text-white text-sm font-medium hover:bg-[#112254] dark:hover:bg-blue-500"
          >
            Saisir le code manuellement
          </button>
        </div>
      </div>
    </div>
  );
};

interface VerifyIdentityViewProps {
  identity: UnlockedIdentity;
  conversation: PeerConversation;
  onConfirmVerified: (peerDeviceId: string, fingerprint: string) => Promise<void>;
  onOpenChat: () => void;
  onBack: () => void;
}

export const VerifyIdentityView: React.FC<VerifyIdentityViewProps> = ({
  identity,
  conversation,
  onConfirmVerified,
  onOpenChat,
  onBack,
}) => {
  const [safetyNumber, setSafetyNumber] = useState<string>('Calcul…');
  const [saving, setSaving] = useState(false);

  const isAlreadyVerified = conversation.verifiedFingerprint === conversation.peer.fingerprint;

  useEffect(() => {
    void computeJointSafetyNumber(toPublicIdentity(identity), conversation.peer).then(
      setSafetyNumber
    );
  }, [identity, conversation.peer]);

  const handleVerify = async () => {
    setSaving(true);
    try {
      await onConfirmVerified(conversation.peer.deviceId, conversation.peer.fingerprint);
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto p-4 sm:p-8 space-y-6">
      <button
        type="button"
        onClick={onBack}
        className="min-h-[44px] px-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] text-sm font-medium flex items-center gap-2 hover:bg-slate-100 dark:hover:bg-slate-800/70"
      >
        <ArrowLeft className="w-4 h-4" />
        Retour
      </button>

      <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] p-6 sm:p-8 space-y-6">
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1">
            <h1 className="font-display text-2xl font-bold text-slate-950 dark:text-white">
              Vérification des identités
            </h1>
            <p className="text-sm text-slate-600 dark:text-slate-300">
              Comparez ce numéro de sécurité avec {conversation.peer.pseudonym} de vive voix ou en
              personne pour écarter toute attaque de l’homme du milieu.
            </p>
          </div>
          {isAlreadyVerified ? (
            <ShieldCheck className="w-7 h-7 text-emerald-500 shrink-0" />
          ) : (
            <ShieldAlert className="w-7 h-7 text-amber-500 shrink-0" />
          )}
        </div>

        <div className="p-5 rounded-2xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#050811] space-y-2">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400">
            Numéro de sécurité commun (60 chiffres)
          </p>
          <p
            data-testid="safety-number"
            className="font-mono text-base sm:text-lg font-semibold tracking-wider text-slate-950 dark:text-white leading-relaxed"
          >
            {safetyNumber}
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 space-y-1.5">
            <p className="text-xs font-medium text-slate-500 dark:text-slate-400">
              Votre empreinte ({identity.pseudonym})
            </p>
            <p className="font-mono text-xs text-slate-800 dark:text-slate-200 break-all leading-relaxed">
              {identity.fingerprint}
            </p>
          </div>
          <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 space-y-1.5">
            <p className="text-xs font-medium text-slate-500 dark:text-slate-400">
              Empreinte de {conversation.peer.pseudonym}
            </p>
            <p className="font-mono text-xs text-slate-800 dark:text-slate-200 break-all leading-relaxed">
              {conversation.peer.fingerprint}
            </p>
          </div>
        </div>

        <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#050811] text-xs text-slate-600 dark:text-slate-300 space-y-1.5 leading-relaxed">
          <p className="font-semibold text-slate-900 dark:text-slate-100">
            Transparence cryptographique
          </p>
          <p>
            eMesh utilise WebCrypto (ECDH P-256 avec clé éphémère par message + HKDF-SHA-256 +
            AES-256-GCM authentifié + signature ECDSA P-256). Ce n’est pas la bibliothèque native
            libsignal (X3DH/Curve25519), mais une implémentation WebCrypto standard auditée au
            niveau navigateur sans algorithme propriétaire.
          </p>
          <p>
            Aucune messagerie ne peut empêcher techniquement la prise de photo externe d’un écran.
          </p>
        </div>

        <div className="flex flex-col sm:flex-row gap-3">
          {!isAlreadyVerified && (
            <button
              type="button"
              onClick={handleVerify}
              disabled={saving}
              className="flex-1 min-h-[48px] px-5 rounded-xl bg-emerald-600 text-white font-medium hover:bg-emerald-500 disabled:opacity-50 flex items-center justify-center gap-2"
            >
              <ShieldCheck className="w-4 h-4" />
              {saving ? 'Enregistrement…' : 'Marquer comme vérifié'}
            </button>
          )}
          <button
            type="button"
            onClick={onOpenChat}
            className="flex-1 min-h-[48px] px-5 rounded-xl bg-[#0A1433] dark:bg-blue-600 text-white font-medium hover:bg-[#112254] dark:hover:bg-blue-500 flex items-center justify-center gap-2"
          >
            Ouvrir la conversation privée
          </button>
        </div>
      </div>
    </div>
  );
};
