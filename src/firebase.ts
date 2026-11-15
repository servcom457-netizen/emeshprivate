import { initializeApp } from 'firebase/app';
import {
  getAuth,
  GoogleAuthProvider,
  onAuthStateChanged,
  signInWithPopup,
  signOut,
  type User,
} from 'firebase/auth';
import {
  doc,
  getDocFromServer,
  getFirestore,
  serverTimestamp,
  setDoc,
  updateDoc,
} from 'firebase/firestore';
import firebaseConfig from '../firebase-applet-config.json';
import type { EncryptedEnvelope, PublicIdentity } from './types';

const app = initializeApp(firebaseConfig);
export const db = getFirestore(app, firebaseConfig.firestoreDatabaseId);
export const auth = getAuth(app);

export const OperationType = {
  CREATE: 'create',
  UPDATE: 'update',
  DELETE: 'delete',
  LIST: 'list',
  GET: 'get',
  WRITE: 'write',
} as const;

export type OperationTypeValue = (typeof OperationType)[keyof typeof OperationType];

export interface FirestoreErrorInfo {
  error: string;
  operationType: OperationTypeValue;
  path: string | null;
  authInfo: {
    userId?: string | null;
    email?: string | null;
    emailVerified?: boolean | null;
    isAnonymous?: boolean | null;
    tenantId?: string | null;
    providerInfo?: {
      providerId?: string | null;
      email?: string | null;
    }[];
  };
}

export function handleFirestoreError(
  error: unknown,
  operationType: OperationTypeValue,
  path: string | null
): never {
  const errInfo: FirestoreErrorInfo = {
    error: error instanceof Error ? error.message : String(error),
    authInfo: {
      userId: auth.currentUser?.uid,
      email: auth.currentUser?.email,
      emailVerified: auth.currentUser?.emailVerified,
      isAnonymous: auth.currentUser?.isAnonymous,
      tenantId: auth.currentUser?.tenantId,
      providerInfo:
        auth.currentUser?.providerData?.map((provider) => ({
          providerId: provider.providerId,
          email: provider.email,
        })) || [],
    },
    operationType,
    path,
  };
  console.error('Firestore Error: ', JSON.stringify(errInfo));
  throw new Error(JSON.stringify(errInfo));
}

async function testConnection() {
  try {
    await getDocFromServer(doc(db, 'test', 'connection'));
  } catch (error) {
    if (error instanceof Error && error.message.includes('the client is offline')) {
      console.error('Please check your Firebase configuration.');
    }
  }
}
void testConnection();

export function subscribeFirebaseAuth(cb: (user: User | null) => void) {
  return onAuthStateChanged(auth, cb);
}

export async function signInTechnicalGoogle(): Promise<User> {
  const provider = new GoogleAuthProvider();
  const res = await signInWithPopup(auth, provider);
  return res.user;
}

export async function signOutTechnicalGoogle(): Promise<void> {
  await signOut(auth);
}

// Optional technical sync: stores ONLY public keys and encrypted envelopes, never private keys or plaintext
export async function syncDeviceIdentityToFirestore(identity: PublicIdentity): Promise<void> {
  const user = auth.currentUser;
  if (!user || !user.emailVerified) return;

  const userPath = `users/${user.uid}`;
  try {
    await setDoc(
      doc(db, 'users', user.uid),
      {
        uid: user.uid,
        pseudonym: identity.pseudonym,
        activeDeviceId: identity.deviceId,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      },
      { merge: true }
    );
  } catch (error) {
    handleFirestoreError(error, OperationType.WRITE, userPath);
  }

  const devicePath = `users/${user.uid}/devices/${identity.deviceId}`;
  try {
    await setDoc(doc(db, 'users', user.uid, 'devices', identity.deviceId), {
      deviceId: identity.deviceId,
      ownerUid: user.uid,
      pseudonym: identity.pseudonym,
      identityPublicKey: identity.identityPublicKey,
      signingPublicKey: identity.signingPublicKey,
      fingerprint: identity.fingerprint,
      revoked: false,
      createdAt: serverTimestamp(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, devicePath);
  }
}

export async function syncEncryptedEnvelopeToFirestore(
  envelope: EncryptedEnvelope,
  recipientUid: string
): Promise<void> {
  const user = auth.currentUser;
  if (!user || !user.emailVerified || !recipientUid) return;

  const path = `conversations/${envelope.conversationId}/messages/${envelope.messageId}`;
  try {
    await setDoc(doc(db, 'conversations', envelope.conversationId, 'messages', envelope.messageId), {
      messageId: envelope.messageId,
      conversationId: envelope.conversationId,
      senderUid: user.uid,
      recipientUid,
      senderDeviceId: envelope.senderDeviceId,
      ciphertext: envelope.ciphertext,
      iv: envelope.iv,
      ephemeralPubKey: envelope.ephemeralPubKey,
      ratchetCounter: envelope.ratchetCounter,
      signature: envelope.signature,
      messageType: envelope.messageType,
      ephemeralTtlMs: envelope.ephemeralTtlMs,
      status: 'sent',
      createdAt: serverTimestamp(),
      expiresAtMs: envelope.expiresAt ?? 0,
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.CREATE, path);
  }
}

export async function markEnvelopeExpiredInFirestore(
  conversationId: string,
  messageId: string
): Promise<void> {
  const user = auth.currentUser;
  if (!user || !user.emailVerified) return;
  const path = `conversations/${conversationId}/messages/${messageId}`;
  try {
    await updateDoc(doc(db, 'conversations', conversationId, 'messages', messageId), {
      status: 'expired',
      expiresAtMs: Date.now(),
    });
  } catch (error) {
    handleFirestoreError(error, OperationType.UPDATE, path);
  }
}
