import React, { useState } from 'react';
import {
  ArrowLeft,
  Cloud,
  KeyRound,
  Lock,
  Moon,
  ShieldAlert,
  ShieldCheck,
  Sun,
  Trash2,
  UserX,
  Users,
} from 'lucide-react';
import type { User } from 'firebase/auth';
import { EPHEMERAL_OPTIONS } from '../types';
import type { EphemeralDurationMs, PeerConversation, UnlockedIdentity } from '../types';

interface SettingsViewProps {
  identity: UnlockedIdentity;
  theme: 'dark' | 'light';
  defaultEphemeralTtlMs: EphemeralDurationMs;
  firebaseUser: User | null;
  onToggleTheme: () => void;
  onUpdatePseudonym: (name: string) => Promise<void>;
  onChangePin: (currentPin: string, newPin: string) => Promise<void>;
  onChangeDefaultTtl: (ttl: EphemeralDurationMs) => void;
  onFirebaseLogin: () => Promise<void>;
  onFirebaseLogout: () => Promise<void>;
  onOpenAssociations: () => void;
  onLockDevice: () => Promise<void>;
  onOpenDeleteAccount: () => void;
  onBack: () => void;
}

export const SettingsView: React.FC<SettingsViewProps> = ({
  identity,
  theme,
  defaultEphemeralTtlMs,
  firebaseUser,
  onToggleTheme,
  onUpdatePseudonym,
  onChangePin,
  onChangeDefaultTtl,
  onFirebaseLogin,
  onFirebaseLogout,
  onOpenAssociations,
  onLockDevice,
  onOpenDeleteAccount,
  onBack,
}) => {
  const [pseudo, setPseudo] = useState(identity.pseudonym);
  const [pseudoMsg, setPseudoMsg] = useState<string | null>(null);
  const [currentPin, setCurrentPin] = useState('');
  const [newPin, setNewPin] = useState('');
  const [confirmPin, setConfirmPin] = useState('');
  const [pinMsg, setPinMsg] = useState<{ type: 'ok' | 'err'; text: string } | null>(null);
  const [cloudMsg, setCloudMsg] = useState<string | null>(null);

  const handleSavePseudo = async (e: React.FormEvent) => {
    e.preventDefault();
    setPseudoMsg(null);
    try {
      await onUpdatePseudonym(pseudo.trim());
      setPseudoMsg('Pseudonyme mis à jour.');
    } catch (err) {
      setPseudoMsg(err instanceof Error ? err.message : 'Erreur.');
    }
  };

  const handlePinSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setPinMsg(null);
    if (!/^\d{4,8}$/.test(newPin)) {
      setPinMsg({ type: 'err', text: 'Le nouveau PIN doit contenir 4 à 8 chiffres.' });
      return;
    }
    if (newPin !== confirmPin) {
      setPinMsg({ type: 'err', text: 'La confirmation du PIN ne correspond pas.' });
      return;
    }
    try {
      await onChangePin(currentPin, newPin);
      setCurrentPin('');
      setNewPin('');
      setConfirmPin('');
      setPinMsg({ type: 'ok', text: 'Code PIN modifié et clés rechiffrées localement.' });
    } catch (err) {
      setPinMsg({
        type: 'err',
        text: err instanceof Error ? err.message : 'Code PIN actuel incorrect.',
      });
    }
  };

  const handleCloudConnect = async () => {
    setCloudMsg(null);
    try {
      await onFirebaseLogin();
      setCloudMsg('Compte technique Firebase associé pour la synchronisation des métadonnées.');
    } catch (err) {
      setCloudMsg(err instanceof Error ? err.message : 'Connexion Firebase annulée.');
    }
  };

  return (
    <div className="max-w-3xl mx-auto p-4 sm:p-8 space-y-6 pb-24 md:pb-10">
      <div className="flex items-center justify-start gap-4">
        <button
          type="button"
          onClick={onBack}
          className="min-h-[44px] px-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] text-sm font-medium flex items-center gap-2 hover:bg-slate-100 dark:hover:bg-slate-800/70"
        >
          <ArrowLeft className="w-4 h-4" />
          Retour
        </button>
        <h1 className="font-display text-xl sm:text-2xl font-bold text-slate-950 dark:text-white">
          Paramètres de sécurité
        </h1>
      </div>

      {/* Identity & Pseudonym */}
      <section className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] p-6 space-y-4">
        <div className="flex items-center justify-between gap-4">
          <h2 className="font-display text-lg font-semibold">Identité de l’appareil</h2>
          <span className="font-mono text-xs text-slate-500 dark:text-slate-400">
            {identity.deviceId}
          </span>
        </div>

        <form onSubmit={handleSavePseudo} className="flex flex-col sm:flex-row gap-3">
          <label htmlFor="settings-pseudo" className="sr-only">
            Modifier le pseudonyme
          </label>
          <input
            id="settings-pseudo"
            type="text"
            value={pseudo}
            onChange={(e) => setPseudo(e.target.value)}
            minLength={2}
            maxLength={40}
            required
            className="flex-1 min-h-[44px] px-4 rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#050811] text-sm focus:outline-none focus:ring-2 focus:ring-blue-600"
          />
          <button
            type="submit"
            className="min-h-[44px] px-5 rounded-xl bg-[#0A1433] dark:bg-blue-600 text-white text-sm font-medium hover:bg-[#112254] dark:hover:bg-blue-500 whitespace-nowrap"
          >
            Enregistrer le pseudonyme
          </button>
        </form>
        {pseudoMsg && <p className="text-xs text-blue-600 dark:text-blue-400">{pseudoMsg}</p>}

        <div className="p-3.5 rounded-xl bg-slate-50 dark:bg-[#050811] border border-slate-200 dark:border-slate-800">
          <p className="text-xs text-slate-500 dark:text-slate-400 mb-1">
            Votre empreinte publique (SHA-256)
          </p>
          <p className="font-mono text-xs break-all text-slate-800 dark:text-slate-200">
            {identity.fingerprint}
          </p>
        </div>
      </section>

      {/* Appearance & Ephemeral default */}
      <section className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] p-6 space-y-5">
        <h2 className="font-display text-lg font-semibold">Confidentialité et affichage</h2>

        <div className="flex items-center justify-between gap-4">
          <div>
            <p className="text-sm font-medium">Apparence de l’interface</p>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Mode sombre bleu nuit ou mode clair
            </p>
          </div>
          <button
            type="button"
            onClick={onToggleTheme}
            className="min-h-[44px] px-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-[#050811] text-sm font-medium flex items-center gap-2 whitespace-nowrap"
          >
            {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
            {theme === 'dark' ? 'Passer en mode clair' : 'Passer en mode sombre'}
          </button>
        </div>

        <div className="space-y-2 pt-2 border-t border-slate-100 dark:border-slate-800">
          <label htmlFor="default-ttl" className="block text-sm font-medium">
            Durée par défaut des messages éphémères
          </label>
          <select
            id="default-ttl"
            value={defaultEphemeralTtlMs}
            onChange={(e) => onChangeDefaultTtl(Number(e.target.value) as EphemeralDurationMs)}
            className="w-full min-h-[44px] px-3 rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#050811] text-sm focus:outline-none focus:ring-2 focus:ring-blue-600"
          >
            {EPHEMERAL_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </div>
      </section>

      {/* Change PIN */}
      <section className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] p-6 space-y-4">
        <div className="flex items-center gap-2">
          <KeyRound className="w-4 h-4 text-blue-600 dark:text-blue-400" />
          <h2 className="font-display text-lg font-semibold">Modifier le code PIN</h2>
        </div>

        <form onSubmit={handlePinSubmit} className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <input
            type="password"
            inputMode="numeric"
            placeholder="PIN actuel"
            aria-label="PIN actuel"
            value={currentPin}
            onChange={(e) => setCurrentPin(e.target.value.replace(/\D/g, ''))}
            required
            className="min-h-[44px] px-3 rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#050811] font-mono text-sm"
          />
          <input
            type="password"
            inputMode="numeric"
            placeholder="Nouveau PIN"
            aria-label="Nouveau PIN"
            value={newPin}
            onChange={(e) => setNewPin(e.target.value.replace(/\D/g, ''))}
            required
            className="min-h-[44px] px-3 rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#050811] font-mono text-sm"
          />
          <input
            type="password"
            inputMode="numeric"
            placeholder="Confirmer"
            aria-label="Confirmer le nouveau PIN"
            value={confirmPin}
            onChange={(e) => setConfirmPin(e.target.value.replace(/\D/g, ''))}
            required
            className="min-h-[44px] px-3 rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#050811] font-mono text-sm"
          />
          <div className="sm:col-span-3 flex items-center justify-between gap-4">
            {pinMsg ? (
              <p
                className={`text-xs ${
                  pinMsg.type === 'ok'
                    ? 'text-emerald-600 dark:text-emerald-400'
                    : 'text-red-600 dark:text-red-400'
                }`}
              >
                {pinMsg.text}
              </p>
            ) : (
              <span />
            )}
            <button
              type="submit"
              className="min-h-[44px] px-5 rounded-xl bg-[#0A1433] dark:bg-blue-600 text-white text-sm font-medium hover:bg-[#112254] dark:hover:bg-blue-500 whitespace-nowrap"
            >
              Mettre à jour le PIN
            </button>
          </div>
        </form>
      </section>

      {/* Firebase technical account (optional) */}
      <section className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] p-6 space-y-3">
        <div className="flex items-center justify-between gap-4 flex-wrap">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <Cloud className="w-4 h-4 text-blue-600 dark:text-blue-400" />
              <h2 className="font-display text-lg font-semibold">
                Synchronisation technique Cloud Firestore (optionnelle)
              </h2>
            </div>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              {firebaseUser
                ? `Connecté en tant que ${firebaseUser.email ?? firebaseUser.uid}. Seules les clés publiques et enveloppes chiffrées sont synchronisées.`
                : 'Non requis pour discuter. Permet uniquement de sauvegarder les enveloppes chiffrées et clés publiques sur Firestore.'}
            </p>
          </div>
          {firebaseUser ? (
            <button
              type="button"
              onClick={() => void onFirebaseLogout()}
              className="min-h-[44px] px-4 rounded-xl border border-slate-200 dark:border-slate-700 text-sm font-medium hover:bg-slate-100 dark:hover:bg-slate-800"
            >
              Déconnecter Firebase
            </button>
          ) : (
            <button
              type="button"
              onClick={handleCloudConnect}
              className="min-h-[44px] px-4 rounded-xl border border-slate-200 dark:border-slate-700 text-sm font-medium hover:bg-slate-100 dark:hover:bg-slate-800"
            >
              Connecter un compte Google
            </button>
          )}
        </div>
        {cloudMsg && <p className="text-xs text-blue-600 dark:text-blue-400">{cloudMsg}</p>}
      </section>

      {/* Associations, Lock, Delete */}
      <section className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] p-6 space-y-3">
        <h2 className="font-display text-lg font-semibold mb-2">Gestion et session</h2>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <button
            type="button"
            onClick={onOpenAssociations}
            className="min-h-[44px] px-4 rounded-xl border border-slate-200 dark:border-slate-700 text-sm font-medium flex items-center justify-center gap-2 hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            <Users className="w-4 h-4" />
            Associations
          </button>
          <button
            type="button"
            onClick={() => void onLockDevice()}
            className="min-h-[44px] px-4 rounded-xl border border-slate-200 dark:border-slate-700 text-sm font-medium flex items-center justify-center gap-2 hover:bg-slate-100 dark:hover:bg-slate-800"
          >
            <Lock className="w-4 h-4" />
            Verrouiller l’appareil
          </button>
          <button
            type="button"
            onClick={onOpenDeleteAccount}
            className="min-h-[44px] px-4 rounded-xl border border-red-300 dark:border-red-900/60 bg-red-50 dark:bg-red-950/30 text-red-700 dark:text-red-300 text-sm font-medium flex items-center justify-center gap-2 hover:bg-red-100 dark:hover:bg-red-950/60"
          >
            <Trash2 className="w-4 h-4" />
            Supprimer l’identité
          </button>
        </div>
      </section>
    </div>
  );
};

interface AssociationsViewProps {
  conversations: PeerConversation[];
  onVerifyPeer: (conv: PeerConversation) => void;
  onOpenChat: (conv: PeerConversation) => void;
  onRevokeConversation: (conversationId: string) => Promise<void>;
  onBack: () => void;
}

export const AssociationsView: React.FC<AssociationsViewProps> = ({
  conversations,
  onVerifyPeer,
  onOpenChat,
  onRevokeConversation,
  onBack,
}) => {
  const [revokingId, setRevokingId] = useState<string | null>(null);

  const handleRevoke = async (id: string) => {
    setRevokingId(id);
    try {
      await onRevokeConversation(id);
    } finally {
      setRevokingId(null);
    }
  };

  return (
    <div className="max-w-3xl mx-auto p-4 sm:p-8 space-y-6 pb-24 md:pb-10">
      <div className="flex items-center justify-between gap-4">
        <button
          type="button"
          onClick={onBack}
          className="min-h-[44px] px-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] text-sm font-medium flex items-center gap-2 hover:bg-slate-100 dark:hover:bg-slate-800/70"
        >
          <ArrowLeft className="w-4 h-4" />
          Retour
        </button>
        <h1 className="font-display text-xl sm:text-2xl font-bold text-slate-950 dark:text-white">
          Gestion des associations
        </h1>
      </div>

      {conversations.length === 0 ? (
        <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] p-8 text-center text-sm text-slate-500 dark:text-slate-400">
          Aucune association enregistrée sur cet appareil.
        </div>
      ) : (
        <div className="space-y-4">
          {conversations.map((conv) => {
            const verified = conv.verifiedFingerprint === conv.peer.fingerprint;
            const revoked = conv.status === 'revoked';
            return (
              <div
                key={conv.conversationId}
                className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] p-5 space-y-4"
              >
                <div className="flex flex-wrap items-center justify-between gap-3">
                  <div>
                    <div className="flex items-center gap-2">
                      <h2 className="font-display text-lg font-semibold text-slate-950 dark:text-white">
                        {conv.peer.pseudonym}
                      </h2>
                      {verified ? (
                        <ShieldCheck className="w-4 h-4 text-emerald-500" />
                      ) : (
                        <ShieldAlert className="w-4 h-4 text-amber-500" />
                      )}
                    </div>
                    <p className="text-xs text-slate-500 dark:text-slate-400">
                      {revoked ? 'Association révoquée' : 'Active'} · Époque de clé #{conv.keyEpoch} ·{' '}
                      {verified ? 'Identité vérifiée' : 'Empreinte non vérifiée'}
                    </p>
                  </div>

                  {!revoked && (
                    <div className="flex flex-wrap gap-2">
                      <button
                        type="button"
                        onClick={() => onVerifyPeer(conv)}
                        className="min-h-[40px] px-3.5 rounded-xl border border-slate-200 dark:border-slate-700 text-xs font-medium hover:bg-slate-100 dark:hover:bg-slate-800"
                      >
                        Vérifier l’empreinte
                      </button>
                      <button
                        type="button"
                        onClick={() => onOpenChat(conv)}
                        className="min-h-[40px] px-3.5 rounded-xl bg-[#0A1433] dark:bg-blue-600 text-white text-xs font-medium hover:bg-[#112254] dark:hover:bg-blue-500"
                      >
                        Ouvrir
                      </button>
                      <button
                        type="button"
                        disabled={revokingId === conv.conversationId}
                        onClick={() => void handleRevoke(conv.conversationId)}
                        className="min-h-[40px] px-3.5 rounded-xl border border-red-300 dark:border-red-900/60 text-red-600 dark:text-red-400 text-xs font-medium hover:bg-red-50 dark:hover:bg-red-950/30 disabled:opacity-50"
                      >
                        {revokingId === conv.conversationId ? 'Révocation…' : 'Révoquer'}
                      </button>
                    </div>
                  )}
                </div>

                <p className="font-mono text-xs text-slate-500 dark:text-slate-400 break-all">
                  {conv.peer.fingerprint}
                </p>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

interface DeleteAccountViewProps {
  hasSession: boolean;
  onConfirmDelete: () => Promise<void>;
  onBack: () => void;
}

export const DeleteAccountView: React.FC<DeleteAccountViewProps> = ({
  hasSession,
  onConfirmDelete,
  onBack,
}) => {
  const [confirmText, setConfirmText] = useState('');
  const [busy, setBusy] = useState(false);

  const handleDelete = async (e: React.FormEvent) => {
    e.preventDefault();
    if (confirmText.trim().toUpperCase() !== 'SUPPRIMER') return;
    setBusy(true);
    try {
      await onConfirmDelete();
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
        Annuler
      </button>

      <div className="rounded-2xl border border-red-200 dark:border-red-900/60 bg-white dark:bg-[#0A1128] p-6 sm:p-8 space-y-5">
        <div className="flex items-center gap-3 text-red-600 dark:text-red-400">
          <UserX className="w-6 h-6 shrink-0" />
          <h1 className="font-display text-2xl font-bold">Suppression de l’identité</h1>
        </div>

        <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
          Cette action est irréversible. Elle révoque {hasSession ? 'vos associations côté serveur, ' : ''}
          détruit vos clés privées dans le coffre local IndexedDB, efface les messages locaux et
          réinitialise cet appareil.
        </p>

        <form onSubmit={handleDelete} className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="delete-confirm" className="block text-sm font-medium">
              Tapez <span className="font-mono font-bold">SUPPRIMER</span> pour confirmer
            </label>
            <input
              id="delete-confirm"
              type="text"
              value={confirmText}
              onChange={(e) => setConfirmText(e.target.value)}
              placeholder="SUPPRIMER"
              required
              className="w-full min-h-[48px] px-4 rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#050811] font-mono text-sm focus:outline-none focus:ring-2 focus:ring-red-600"
            />
          </div>

          <button
            type="submit"
            disabled={busy || confirmText.trim().toUpperCase() !== 'SUPPRIMER'}
            className="w-full min-h-[48px] px-5 rounded-xl bg-red-600 text-white font-medium hover:bg-red-500 disabled:opacity-40 transition-colors"
          >
            {busy ? 'Destruction des clés et données…' : 'Supprimer définitivement mon identité'}
          </button>
        </form>
      </div>
    </div>
  );
};
