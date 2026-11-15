# eMesh — Messagerie Privée Sécurisée

**Slogan :** *Votre confidentialité, votre liberté.*

Application web responsive (ordinateur, tablette, smartphone Android) de messagerie privée pair-à-pair chiffrée de bout en bout, sans exigence de numéro de téléphone ou d’adresse e-mail pour l’association.

## 1. Architecture technique

- **Frontend (`src/`)** : React 19 + TypeScript + Tailwind CSS v4 (mode sombre bleu nuit / noir / blanc et mode clair).
- **Cryptographie (`src/crypto/emeshCrypto.ts`)** :
  - Identité locale : paires de clés **ECDH P-256** (accord de clé) et **ECDSA P-256** (signature et authentification) générées localement via l’API WebCrypto (`crypto.subtle`).
  - Coffre local (`src/storage/localVault.ts`) : clés privées chiffrées au repos dans **IndexedDB** par **AES-256-GCM** avec une clé dérivée du code PIN via **PBKDF2 (SHA-256, 210 000 itérations)**.
  - Chiffrement de bout en bout des messages : dérivation par message via **ECDH éphémère + HKDF-SHA-256** et chiffrement authentifié **AES-256-GCM** (AAD liant conversation, expéditeur, époque et compteur), signé par **ECDSA P-256**.
  - Médias (voix, photos, vidéos, documents) : chiffrés sur l’appareil avant envoi par **AES-256-GCM** avec une clé aléatoire unique transmise uniquement dans l’enveloppe chiffrée.
- **Backend (`server.ts`, `server/securityStore.ts`)** :
  - Node.js + Express + WebSocket (`ws`).
  - Authentification par défi cryptographique signé (`ECDSA`) + jetons de session signés (`HMAC-SHA256`).
  - Codes de connexion à usage unique (10 caractères, validité 10 minutes, invalidation immédiate, limitation des tentatives).
  - Isolation stricte à 2 participants par conversation.
  - Stockage temporaire des blobs chiffrés (`.emesh-blobs/`) purgé automatiquement à l’expiration des messages éphémères.
- **Firebase (`src/firebase.ts`, `firestore.rules`, `firebase-blueprint.json`)** :
  - Synchronisation technique optionnelle des clés publiques et enveloppes chiffrées sous règles Firestore strictes (`rules_version = '2'`). Aucune clé privée ni aucun texte en clair n’est jamais stocké dans Firestore.

## 2. Limites de sécurité assumées (transparence)

1. **WebCrypto vs libsignal natif** : eMesh implémente une dérivation de clés éphémères par message (ECDH P-256 + HKDF-SHA-256 + AES-256-GCM + ECDSA P-256) via WebCrypto, mais n’intègre pas la bibliothèque native `libsignal` (X3DH / Curve25519 / Double Ratchet formel).
2. **Protection physique de l’écran** : aucune application web ou mobile ne peut empêcher de manière absolue une photographie externe de l’écran ou une capture matérielle.
3. **Stockage navigateur** : sur navigateur, le coffre repose sur IndexedDB + WebCrypto (et non sur un enclave matérielle Android Keystore / StrongBox native).

## 3. Installation et lancement en local

```bash
npm install
npm test
npm run dev
```

L’application démarre sur `http://localhost:3000`.

## 4. Tester sur deux téléphones Android

1. Démarrez le serveur sur votre poste ou déployez sur une URL HTTPS publique (`APP_URL`). (L’accès caméra et microphone sur Android Chrome requiert HTTPS ou `localhost`).
2. Ouvrez l’URL de l’application sur le **Téléphone A** et le **Téléphone B**.
3. Sur chaque téléphone, créez une identité (pseudonyme + code PIN).
4. Sur le **Téléphone A**, ouvrez **Connecter un correspondant** pour afficher le code unique et le QR code.
5. Sur le **Téléphone B**, ouvrez **Scanner un QR code** (ou **Rejoindre avec un code**), scannez le QR code de A.
6. Comparez le **Numéro de sécurité commun** à 60 chiffres sur les deux écrans, marquez comme vérifié, puis testez messages texte, notes vocales, photos, vidéos, documents et suppression éphémère.

## 5. Déploiement

```bash
npm run build
NODE_ENV=production npm start
```

Pour déployer les règles Firestore sur votre projet Firebase :

```bash
firebase deploy --only firestore:rules
```
