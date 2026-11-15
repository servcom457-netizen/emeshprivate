import type { DecryptedMessage, EphemeralDurationMs, WrappedVaultRecord } from '../types';

const DB_NAME = 'emesh-secure-vault';
const DB_VERSION = 1;
const VAULT_STORE = 'vault';
const PEERS_STORE = 'verified_peers';
const MESSAGES_STORE = 'local_messages';
const PREFS_KEY = 'emesh_prefs_v1';

export interface AppPreferences {
  theme: 'dark' | 'light';
  defaultEphemeralTtlMs: EphemeralDurationMs;
}

const DEFAULT_PREFS: AppPreferences = {
  theme: 'dark',
  defaultEphemeralTtlMs: 30000,
};

function openVaultDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(VAULT_STORE)) {
        db.createObjectStore(VAULT_STORE);
      }
      if (!db.objectStoreNames.contains(PEERS_STORE)) {
        db.createObjectStore(PEERS_STORE);
      }
      if (!db.objectStoreNames.contains(MESSAGES_STORE)) {
        db.createObjectStore(MESSAGES_STORE);
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error ?? new Error('Impossible d’ouvrir le coffre IndexedDB.'));
  });
}

async function idbGet<T>(storeName: string, key: string): Promise<T | null> {
  const db = await openVaultDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readonly');
    const store = tx.objectStore(storeName);
    const req = store.get(key);
    req.onsuccess = () => resolve((req.result as T) ?? null);
    req.onerror = () => reject(req.error);
  });
}

async function idbPut<T>(storeName: string, key: string, value: T): Promise<void> {
  const db = await openVaultDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    tx.objectStore(storeName).put(value, key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

async function idbDelete(storeName: string, key: string): Promise<void> {
  const db = await openVaultDb();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(storeName, 'readwrite');
    tx.objectStore(storeName).delete(key);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function saveVaultRecord(record: WrappedVaultRecord): Promise<void> {
  await idbPut(VAULT_STORE, 'primary', record);
}

export async function loadVaultRecord(): Promise<WrappedVaultRecord | null> {
  return idbGet<WrappedVaultRecord>(VAULT_STORE, 'primary');
}

export async function saveVerifiedPeerFingerprint(
  peerDeviceId: string,
  fingerprint: string
): Promise<void> {
  await idbPut(PEERS_STORE, peerDeviceId, {
    fingerprint,
    verifiedAt: Date.now(),
  });
}

export async function getVerifiedPeerFingerprint(peerDeviceId: string): Promise<string | null> {
  const res = await idbGet<{ fingerprint: string; verifiedAt: number }>(PEERS_STORE, peerDeviceId);
  return res?.fingerprint ?? null;
}

export async function saveLocalMessages(
  conversationId: string,
  messages: DecryptedMessage[]
): Promise<void> {
  const now = Date.now();
  const nonExpired = messages.filter(
    (m) => m.status !== 'expired' && !(typeof m.expiresAt === 'number' && now >= m.expiresAt)
  );
  await idbPut(MESSAGES_STORE, conversationId, nonExpired);
}

export async function loadLocalMessages(conversationId: string): Promise<DecryptedMessage[]> {
  const list = (await idbGet<DecryptedMessage[]>(MESSAGES_STORE, conversationId)) ?? [];
  const now = Date.now();
  return list.filter(
    (m) => m.status !== 'expired' && !(typeof m.expiresAt === 'number' && now >= m.expiresAt)
  );
}

export async function purgeLocalConversation(conversationId: string): Promise<void> {
  await idbDelete(MESSAGES_STORE, conversationId);
}

export async function wipeAllLocalVaultData(): Promise<void> {
  const db = await openVaultDb();
  await Promise.all([
    new Promise<void>((resolve, reject) => {
      const tx = db.transaction([VAULT_STORE, PEERS_STORE, MESSAGES_STORE], 'readwrite');
      tx.objectStore(VAULT_STORE).clear();
      tx.objectStore(PEERS_STORE).clear();
      tx.objectStore(MESSAGES_STORE).clear();
      tx.oncomplete = () => resolve();
      tx.onerror = () => reject(tx.error);
    }),
  ]);
  localStorage.removeItem(PREFS_KEY);
}

export function loadPreferences(): AppPreferences {
  try {
    const raw = localStorage.getItem(PREFS_KEY);
    if (!raw) return DEFAULT_PREFS;
    const parsed = JSON.parse(raw) as Partial<AppPreferences>;
    return {
      theme: parsed.theme === 'light' ? 'light' : 'dark',
      defaultEphemeralTtlMs:
        typeof parsed.defaultEphemeralTtlMs === 'number'
          ? parsed.defaultEphemeralTtlMs
          : DEFAULT_PREFS.defaultEphemeralTtlMs,
    };
  } catch {
    return DEFAULT_PREFS;
  }
}

export function savePreferences(prefs: AppPreferences): void {
  localStorage.setItem(PREFS_KEY, JSON.stringify(prefs));
}
