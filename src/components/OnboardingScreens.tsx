import React, { useState } from 'react';
import { ArrowRight, KeyRound, Lock, Moon, ShieldCheck, Sun } from 'lucide-react';
import { EmeshLogo } from './EmeshLogo';
import type { UnlockedIdentity, WrappedVaultRecord } from '../types';

interface SplashScreenProps {
  hasExistingVault: boolean;
  theme: 'dark' | 'light';
  onToggleTheme: () => void;
  onStartCreate: () => void;
  onGoUnlock: () => void;
}

export const SplashScreen: React.FC<SplashScreenProps> = ({
  hasExistingVault,
  theme,
  onToggleTheme,
  onStartCreate,
  onGoUnlock,
}) => {
  return (
    <div className="min-h-screen flex flex-col bg-slate-50 text-slate-950 dark:bg-[#050811] dark:text-slate-50">
      <header className="w-full max-w-6xl mx-auto px-6 py-5 flex items-center justify-between gap-8">
        <div className="flex items-center gap-3 shrink-0">
          <EmeshLogo size={36} />
          <span className="font-display text-xl font-bold tracking-tight whitespace-nowrap">
            eMesh
          </span>
        </div>

        <button
          type="button"
          onClick={onToggleTheme}
          aria-label={theme === 'dark' ? 'Activer le mode clair' : 'Activer le mode sombre'}
          className="min-h-[44px] min-w-[44px] px-3 rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] text-slate-700 dark:text-slate-200 flex items-center justify-center gap-2 text-sm font-medium hover:bg-slate-100 dark:hover:bg-[#111C3D] transition-colors whitespace-nowrap shrink-0"
        >
          {theme === 'dark' ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
          <span className="hidden sm:inline">{theme === 'dark' ? 'Clair' : 'Sombre'}</span>
        </button>
      </header>

      <main className="flex-1 w-full max-w-6xl mx-auto px-6 py-8 md:py-16 grid grid-cols-1 lg:grid-cols-12 gap-12 items-center">
        <div className="lg:col-span-7 space-y-8">
          <div className="space-y-4">
            <p className="text-sm font-medium text-blue-700 dark:text-blue-400">
              Messagerie privée pair-à-pair · Sans téléphone ni e-mail
            </p>
            <h1 className="font-display text-4xl sm:text-5xl lg:text-6xl font-bold tracking-tight leading-[1.08] text-slate-950 dark:text-white [text-wrap:balance]">
              Votre confidentialité, votre liberté.
            </h1>
            <p className="text-base sm:text-lg text-slate-600 dark:text-slate-300 max-w-2xl leading-relaxed">
              Échangez messages, notes vocales, photos, vidéos et documents avec un seul correspondant
              associé. Vos clés privées sont générées sur votre appareil et ne touchent jamais le serveur.
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-4">
            {hasExistingVault ? (
              <button
                type="button"
                onClick={onGoUnlock}
                className="min-h-[48px] px-6 py-3 rounded-xl bg-[#0A1433] dark:bg-blue-600 text-white font-medium text-base flex items-center gap-2.5 hover:bg-[#112254] dark:hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0"
              >
                <Lock className="w-4 h-4" />
                Déverrouiller mon coffre
                <ArrowRight className="w-4 h-4" />
              </button>
            ) : (
              <button
                type="button"
                onClick={onStartCreate}
                className="min-h-[48px] px-6 py-3 rounded-xl bg-[#0A1433] dark:bg-blue-600 text-white font-medium text-base flex items-center gap-2.5 hover:bg-[#112254] dark:hover:bg-blue-500 transition-colors whitespace-nowrap shrink-0"
              >
                <KeyRound className="w-4 h-4" />
                Créer mon identité
                <ArrowRight className="w-4 h-4" />
              </button>
            )}
          </div>
        </div>

        <div className="lg:col-span-5">
          <div className="rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] p-6 sm:p-8 space-y-6">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded-xl bg-blue-950/10 dark:bg-blue-500/15 flex items-center justify-center text-blue-700 dark:text-blue-400">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <div>
                <h2 className="font-display text-lg font-semibold text-slate-950 dark:text-white">
                  Architecture zéro-connaissance
                </h2>
                <p className="text-xs text-slate-500 dark:text-slate-400">
                  WebCrypto ECDH P-256 · ECDSA · AES-256-GCM
                </p>
              </div>
            </div>

            <div className="divide-y divide-slate-100 dark:divide-slate-800/80 text-sm">
              <div className="py-3.5 flex items-start justify-between gap-4">
                <span className="font-medium text-slate-900 dark:text-slate-100">
                  Association par code unique
                </span>
                <span className="text-slate-500 dark:text-slate-400 text-right">
                  Usage unique · 10 min
                </span>
              </div>
              <div className="py-3.5 flex items-start justify-between gap-4">
                <span className="font-medium text-slate-900 dark:text-slate-100">
                  Conversation isolée à deux
                </span>
                <span className="text-slate-500 dark:text-slate-400 text-right">
                  Tiers strictement bloqués
                </span>
              </div>
              <div className="py-3.5 flex items-start justify-between gap-4">
                <span className="font-medium text-slate-900 dark:text-slate-100">
                  Messages et médias éphémères
                </span>
                <span className="text-slate-500 dark:text-slate-400 text-right">
                  Purge locale et serveur
                </span>
              </div>
              <div className="py-3.5 flex items-start justify-between gap-4">
                <span className="font-medium text-slate-900 dark:text-slate-100">
                  Clé privée verrouillée par PIN
                </span>
                <span className="text-slate-500 dark:text-slate-400 text-right">
                  PBKDF2 · IndexedDB
                </span>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
};

interface CreateIdentityViewProps {
  onBack: () => void;
  onIdentityGenerated: (identity: UnlockedIdentity) => void;
  generateIdentity: (pseudonym: string) => Promise<UnlockedIdentity>;
}

export const CreateIdentityView: React.FC<CreateIdentityViewProps> = ({
  onBack,
  onIdentityGenerated,
  generateIdentity,
}) => {
  const [pseudonym, setPseudonym] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    const trimmed = pseudonym.trim();
    if (trimmed.length < 2 || trimmed.length > 40) {
      setError('Veuillez saisir un pseudonyme entre 2 et 40 caractères.');
      return;
    }
    setBusy(true);
    try {
      const identity = await generateIdentity(trimmed);
      onIdentityGenerated(identity);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Erreur lors de la génération des clés.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4 py-10 bg-slate-50 dark:bg-[#050811] text-slate-950 dark:text-slate-50">
      <div className="w-full max-w-lg rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] p-6 sm:p-8 space-y-6">
        <div className="flex items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <EmeshLogo size={32} />
            <span className="font-display font-semibold text-base">Étape 1 sur 2</span>
          </div>
          <button
            type="button"
            onClick={onBack}
            className="min-h-[44px] px-3 rounded-lg text-sm font-medium text-slate-600 dark:text-slate-300 hover:bg-slate-100 dark:hover:bg-slate-800/60 transition-colors"
          >
            Retour
          </button>
        </div>

        <div className="space-y-2">
          <h1 className="font-display text-2xl sm:text-3xl font-bold text-slate-950 dark:text-white">
            Créer votre identité cryptographique
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
            Aucun numéro de téléphone ni adresse e-mail n’est requis. Votre appareil génère
            localement une paire de clés ECDH P-256 (échange de clés) et ECDSA P-256 (signature).
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-5">
          <div className="space-y-2">
            <label
              htmlFor="emesh-pseudonym"
              className="block text-sm font-medium text-slate-800 dark:text-slate-200"
            >
              Pseudonyme affiché à votre correspondant
            </label>
            <input
              id="emesh-pseudonym"
              type="text"
              value={pseudonym}
              onChange={(e) => setPseudonym(e.target.value)}
              placeholder="Ex. Camille, Atlas, Poste-01"
              maxLength={40}
              autoFocus
              required
              className="w-full min-h-[48px] px-4 rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#050811] text-slate-950 dark:text-white placeholder:text-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-600"
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
            className="w-full min-h-[48px] px-5 py-3 rounded-xl bg-[#0A1433] dark:bg-blue-600 text-white font-medium text-base hover:bg-[#112254] dark:hover:bg-blue-500 disabled:opacity-50 transition-colors flex items-center justify-center gap-2"
          >
            <KeyRound className="w-4 h-4" />
            {busy ? 'Génération des clés sur l’appareil…' : 'Générer mes clés et continuer'}
          </button>
        </form>
      </div>
    </div>
  );
};

interface PinSetupViewProps {
  identity: UnlockedIdentity;
  onComplete: (pin: string) => Promise<void>;
}

export const PinSetupView: React.FC<PinSetupViewProps> = ({ identity, onComplete }) => {
  const [pin, setPin] = useState('');
  const [confirmPin, setConfirmPin] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    if (!/^\d{4,8}$/.test(pin)) {
      setError('Le code PIN doit comporter entre 4 et 8 chiffres.');
      return;
    }
    if (pin !== confirmPin) {
      setError('Les deux codes PIN ne correspondent pas.');
      return;
    }
    setBusy(true);
    try {
      await onComplete(pin);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Erreur lors du chiffrement local.');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4 py-10 bg-slate-50 dark:bg-[#050811] text-slate-950 dark:text-slate-50">
      <div className="w-full max-w-lg rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] p-6 sm:p-8 space-y-6">
        <div className="flex items-center gap-3">
          <EmeshLogo size={32} />
          <span className="font-display font-semibold text-base">Étape 2 sur 2 · Protection locale</span>
        </div>

        <div className="space-y-2">
          <h1 className="font-display text-2xl sm:text-3xl font-bold text-slate-950 dark:text-white">
            Configurer votre code PIN
          </h1>
          <p className="text-sm text-slate-600 dark:text-slate-300 leading-relaxed">
            Ce code PIN dérive une clé AES-256-GCM (PBKDF2) qui chiffre vos clés privées dans le
            stockage local de cet appareil. Il n’est jamais envoyé au serveur.
          </p>
        </div>

        <div className="p-4 rounded-xl border border-slate-200 dark:border-slate-800 bg-slate-50 dark:bg-[#050811] space-y-1">
          <p className="text-xs text-slate-500 dark:text-slate-400">
            Empreinte cryptographique générée ({identity.pseudonym})
          </p>
          <p className="font-mono text-xs text-slate-800 dark:text-slate-200 break-all leading-relaxed">
            {identity.fingerprint}
          </p>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="pin-input" className="block text-sm font-medium">
              Code PIN (4 à 8 chiffres)
            </label>
            <input
              id="pin-input"
              type="password"
              inputMode="numeric"
              pattern="\d{4,8}"
              maxLength={8}
              value={pin}
              onChange={(e) => setPin(e.target.value.replace(/\D/g, ''))}
              placeholder="••••"
              autoFocus
              required
              className="w-full min-h-[48px] px-4 rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#050811] font-mono text-lg tracking-widest focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>

          <div className="space-y-2">
            <label htmlFor="pin-confirm" className="block text-sm font-medium">
              Confirmer le code PIN
            </label>
            <input
              id="pin-confirm"
              type="password"
              inputMode="numeric"
              pattern="\d{4,8}"
              maxLength={8}
              value={confirmPin}
              onChange={(e) => setConfirmPin(e.target.value.replace(/\D/g, ''))}
              placeholder="••••"
              required
              className="w-full min-h-[48px] px-4 rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#050811] font-mono text-lg tracking-widest focus:outline-none focus:ring-2 focus:ring-blue-600"
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
            className="w-full min-h-[48px] px-5 py-3 rounded-xl bg-[#0A1433] dark:bg-blue-600 text-white font-medium text-base hover:bg-[#112254] dark:hover:bg-blue-500 disabled:opacity-50 transition-colors flex items-center justify-center gap-2"
          >
            <Lock className="w-4 h-4" />
            {busy ? 'Chiffrement du coffre…' : 'Verrouiller et accéder à eMesh'}
          </button>
        </form>
      </div>
    </div>
  );
};

interface PinLockViewProps {
  vault: WrappedVaultRecord;
  onUnlock: (pin: string) => Promise<void>;
  onGoDeleteAccount: () => void;
}

export const PinLockView: React.FC<PinLockViewProps> = ({
  vault,
  onUnlock,
  onGoDeleteAccount,
}) => {
  const [pin, setPin] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [failedCount, setFailedCount] = useState(0);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);
    setBusy(true);
    try {
      await onUnlock(pin);
    } catch (err) {
      setFailedCount((c) => c + 1);
      setError(err instanceof Error ? err.message : 'Code PIN incorrect.');
      setPin('');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center px-4 py-10 bg-slate-50 dark:bg-[#050811] text-slate-950 dark:text-slate-50">
      <div className="w-full max-w-md rounded-2xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-[#0A1128] p-6 sm:p-8 space-y-6">
        <div className="flex items-center gap-3">
          <EmeshLogo size={36} />
          <div>
            <h1 className="font-display text-xl font-bold text-slate-950 dark:text-white">
              Coffre verrouillé
            </h1>
            <p className="text-xs text-slate-500 dark:text-slate-400">
              Identité locale · {vault.pseudonym}
            </p>
          </div>
        </div>

        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="space-y-2">
            <label htmlFor="unlock-pin" className="block text-sm font-medium">
              Saisissez votre code PIN
            </label>
            <input
              id="unlock-pin"
              type="password"
              inputMode="numeric"
              maxLength={8}
              value={pin}
              onChange={(e) => setPin(e.target.value.replace(/\D/g, ''))}
              placeholder="••••"
              autoFocus
              required
              className="w-full min-h-[48px] px-4 rounded-xl border border-slate-300 dark:border-slate-700 bg-slate-50 dark:bg-[#050811] font-mono text-xl tracking-[0.4em] text-center focus:outline-none focus:ring-2 focus:ring-blue-600"
            />
          </div>

          {error && (
            <div
              role="alert"
              className="p-3.5 rounded-xl border border-red-300 dark:border-red-900/60 bg-red-50 dark:bg-red-950/30 text-sm text-red-700 dark:text-red-300"
            >
              {error} {failedCount >= 3 ? 'Vérifiez vos chiffres ou réinitialisez le coffre.' : ''}
            </div>
          )}

          <button
            type="submit"
            disabled={busy || pin.length < 4}
            className="w-full min-h-[48px] px-5 py-3 rounded-xl bg-[#0A1433] dark:bg-blue-600 text-white font-medium text-base hover:bg-[#112254] dark:hover:bg-blue-500 disabled:opacity-50 transition-colors"
          >
            {busy ? 'Déchiffrement des clés…' : 'Déverrouiller'}
          </button>
        </form>

        <div className="pt-2 border-t border-slate-100 dark:border-slate-800 flex justify-between items-center text-xs">
          <span className="text-slate-500 dark:text-slate-400">PIN oublié ?</span>
          <button
            type="button"
            onClick={onGoDeleteAccount}
            className="min-h-[36px] text-red-600 dark:text-red-400 font-medium hover:underline"
          >
            Effacer les données locales
          </button>
        </div>
      </div>
    </div>
  );
};
