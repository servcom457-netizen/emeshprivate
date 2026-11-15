# eMesh Firestore Security Specification

## 1. Data Invariants
1. **Zero Plaintext / Zero Private Key Invariant**: Firestore documents never store private keys, PIN hashes, pairing secrets, or plaintext message contents.
2. **Strict 1-to-1 Isolation**: Every `/conversations/{conversationId}` document has exactly two immutable participant UIDs (`creatorUid` and `peerUid`, where `creatorUid != peerUid`). A third authenticated user can never read, list, create, update, or delete the conversation or its `/messages` subcollection.
3. **Owner-Only Profile & Device Control**: Only the owner (`request.auth.uid == userId`) can read, list, create, update, or delete `/users/{userId}` and `/users/{userId}/devices/{deviceId}` (except verified revocation updates).
4. **Master Gate Sync**: Every read/write on `/conversations/{conversationId}/messages/{messageId}` fetches the parent `/conversations/{conversationId}` via `get()` and requires `status == 'active'` and membership (`creatorUid == uid || peerUid == uid`).
5. **Terminal State Locking**: Once a conversation reaches `status == 'revoked'`, no further updates are permitted on the conversation or messages inside it.
6. **Temporal Integrity**: `createdAt` and `updatedAt` must match `request.time`.

## 2. Dirty Dozen Attack Payloads (All Must Return PERMISSION_DENIED)
1. Unauthenticated read on `/users/{uid}`.
2. User B attempting `get` or `list` on User A's `/users/{uidA}`.
3. User A creating `/users/{uidA}` with a ghost field `isAdmin: true` (blocked by `hasOnly`).
4. User A creating `/users/{uidA}/devices/{dev1}` with `ownerUid: uidB` (Identity spoofing).
5. User A creating `/users/{uidA}/devices/{dev1}` with `email_verified: false` (Unverified token).
6. User C (3rd party) attempting `get` on `/conversations/{convAB}` where only A and B are participants.
7. User C attempting `list` on `/conversations` without matching `creatorUid` or `peerUid`.
8. User A creating `/conversations/{convId}` where `creatorUid == peerUid` (Self-pair bypass) or `status == 'revoked'` on creation.
9. User A updating `/conversations/{convAB}` to replace `peerUid` with `uidC` (Immutable participant hijacking).
10. User B updating a `revoked` conversation back to `active` (Terminal state violation).
11. User C creating an encrypted envelope in `/conversations/{convAB}/messages/{msg1}` (Unauthorized injection).
12. User A creating a message with `senderUid: uidB`, oversized `ciphertext` (> 65536 chars), or forged `createdAt` != `request.time`.
