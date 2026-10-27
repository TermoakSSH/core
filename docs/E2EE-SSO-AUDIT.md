# End-to-end encrypted vaults, SSO/OIDC for teams and extended audit (Termoak 0.7, phase 5a)

Status: phases **5a** (2026-10-26), **5b** (2026-10-27, §10) and **5c**
(2026-10-27, Android + iOS, §11; core v0.7.0-next.13) done. Phase 5a:
design (this file; identical copies in
`server/docs/E2EE-SSO-AUDIT.md` and `core/docs/E2EE-SSO-AUDIT.md`), core
v0.7.0-next.10, server 0.7.0-next.10 (staging next.termoak.com, schema
v14), QA suites `e2ee`, `sso`, `audit` and a compat section. The apps'
interfaces come in 5b (web + desktop, §10) and 5c (Android + iOS, §11).
Plan: `PLAN-0.7.md` §3 items 1, 2 and 5. Builds on `VAULTS-MULTISERVER.md`
(vault keys and the reserved E2EE tables, §3.5), `TEAMS-SECURITY.md` (roles,
team policies, CA, how the server resolves secrets) and `PUSH.md`.

## 0. Summary

- **E2EE vaults (optional, per vault).** A vault manager turns it on from a
  device. Each vault gets a 256-bit vault key (VK) made on the device; the
  secrets of its items are sealed with it (AES-256-GCM) and the VK is
  wrapped for every member who may read secrets, with HPKE (RFC 9180) to
  that member's X25519 **user key**. The server keeps only blobs it cannot
  open and deletes its own key of the vault. Metadata (labels, addresses,
  usernames, notes) stays readable by the server: only secrets are
  end-to-end encrypted (decision §9.1).
- **User keys** reach a device through the person: their **E2EE
  passphrase** (Argon2id, never the login password), their **recovery
  key** (256 bits shown once as 24 words) or **another unlocked device** (pairing
  confirmed with a six-digit code). This also answers SSO accounts: an
  identity provider cannot derive a key, so SSO users unlock the same way.
- **What the server can no longer do** for an E2EE vault: reveal, just-in-time
  credentials, server-side moves/copies with secrets, server sessions /
  host tests / exec / the server AI with secrets. What still works: **team
  certificates** (the CA is the server's and needs no vault secret),
  **per-session unlock** (the device sends one host's credentials for one
  server session or test), private networks (their secret stays with the
  server, which joins them), recordings (not end-to-end encrypted).
- **Old clients never see E2EE vaults**: only clients that declare `e2ee`
  in `X-Termoak-Features` (or `features=e2ee` on the events socket) get
  them; others lose their local copy at the next sync and cannot push to
  them. An E2EE personal vault makes the legacy sync answer 409
  `e2ee_client_required`. Nothing is corrupted or silently changed.
- **SSO / OIDC for teams.** Authorization code flow with PKCE towards the
  identity provider **and** between the app and the server (one-time code +
  verifier), ID tokens verified with the provider's keys (RS256/384/512,
  PS*, ES256/384, EdDSA). Presets for Google Workspace, Microsoft Entra,
  Keycloak, Authentik, plus any provider with discovery. A team proves a
  domain with a DNS TXT record; with **enforce**, accounts of that domain
  must sign in through SSO (password sign-in, sign-up and reset refused
  with `sso_required`; the team owner keeps a break-glass password). New
  people of the domain get an account automatically and join the team.
- **Extended audit.** Every entry can belong to a team (`team_id`). Search
  with filters (actions with `*` prefixes, actor, vault, target, time
  range, free text, paging both ways), export (CSV, JSON, NDJSON),
  configurable retention (server default, per-team override), and **SIEM
  sinks**: webhooks (JSON batches signed with HMAC-SHA256) and syslog
  (RFC 5424 over TCP or TLS, RFC 6587 octet counting), delivered in order,
  at least once, with a cursor that survives restarts.

## 1. Goals and non-goals

Goals:
- A vault whose secrets a compromised server (or its operator, or a
  database leak) cannot read, without losing the team features that do not
  need secrets, and with honest, visible trade-offs where they do.
- Only well-known primitives (RustCrypto: x25519-dalek, hkdf, sha2,
  aes-gcm, argon2; HPKE per RFC 9180 checked against its test vector), a
  byte-exact format pinned by shared vectors that the web (WebCrypto) can
  implement (it already does, in the QA suite: §2.2).
- Sign-in through a team's identity provider from every app, with the
  team's domain enforced, without weakening accounts that do not use it.
- An audit trail a team can query, export, keep for as long as it needs and
  feed to its SIEM.

Non-goals (this phase):
- Encrypting metadata (§9.1), recordings (§2.6) or the server's own data.
- SCIM provisioning, SAML, server-wide (non-team) SSO (§12).
- Defending against a malicious server that adds itself as a vault member:
  members are confirmed by key holders with fingerprints (§2.4), which is
  where that attack is caught.
- The apps' interfaces (5b, 5c).

## 2. End-to-end encrypted vaults

### 2.1 Threat model and scope

Protected: the `secret` of every item of an E2EE vault (host passwords and
proxy passwords, identity passwords, private keys and passphrases, snippet
and forward secrets if any). The server stores them as blobs sealed by a
client and never holds a key that opens them. A database dump, a backup,
an operator or a server process compromised **later** cannot read them.

Not protected (and said in the apps): item metadata; the terminal content
of server sessions; secrets a member sends for a per-session unlock (the
server uses them for that connection and wipes them); private network keys
(the server needs them to join the network); recordings. A server
compromised **while** a member uses it can still serve a modified web app
or swap a new member's public key: the native apps' code is not served by
the server, and new members are confirmed with fingerprints.

### 2.2 Cryptography and formats

All blobs start with a version byte `1`; binary values travel as standard
base64 with padding.

| What | Construction | AAD (UTF-8) |
|---|---|---|
| Secret of an item | AES-256-GCM(VK, 12-byte random nonce): `[1][nonce][ct+tag]` | `termoak:e2ee:secret:{vault}:{version}:{kind}:{id}` |
| VK wrapped for a member | HPKE base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, single shot, `info` = `termoak e2ee v1 vault key`: `[1][enc 32][ct+tag]` | `termoak:e2ee:vk:{vault}:{version}:{user}:{key_id}` |
| User private key, passphrase copy | AES-256-GCM(KEK = Argon2id(passphrase, 16-byte salt, m = 64 MiB, t = 3, p = 1)) | `termoak:e2ee:uk:{user}:{key_id}:passphrase` |
| User private key, recovery copy | AES-256-GCM(KEK = HKDF-SHA256(ikm = recovery key, salt = `termoak:e2ee:recovery:v1`, info = `{user}:{key_id}`)) | `termoak:e2ee:uk:{user}:{key_id}:recovery` |
| Pairing hand-over | HPKE as above to the new device's ephemeral key, `info` = `termoak e2ee v1 pairing`, plaintext = key id (16 bytes) ‖ private key | `termoak:e2ee:pairing:{user}:{pairing}` |

- **Fingerprint** of a public key: the first 16 bytes of its SHA-256 as
  eight groups of four hex digits (`3f2a 9c01 …`).
- **Recovery key** (since core v0.7.0-next.11, decision §9.5): 32 random
  bytes shown as a **24-word BIP39 English phrase**: the 32 bytes are the
  BIP39 entropy and the first byte of their SHA-256 is the checksum (264
  bits, 24 words of 11 bits) from the standard word list (`bip-0039/
  english.txt` of bitcoin/bips, embedded in every implementation and
  checked against its SHA-256 `2f5eed53…3b24dbda`). The derivation is the
  same as before: the 32 bytes (not BIP39's PBKDF2 seed, a wallet thing)
  are the HKDF input of the recovery KEK above; the phrase is only their
  encoding. Typing: case, spaces, line breaks, numbering and punctuation
  are ignored, and a word can be shortened to its first four letters (or
  more: BIP39 words are unique in their first four). Refusals are
  `e2ee_recovery_key_invalid` with `detail.reason`: `word_count`
  (`detail.words`), `unknown_word` (`detail.word`, 1-based), `checksum`
  (a mistyped or swapped word) or `old_format` (the first format, 56 base32
  characters, used by no real account and no longer accepted). The vectors
  carry Trezor's 256-bit BIP39 vectors and typed-phrase cases.
- **Pairing code**: `SHA-256("termoak:e2ee:pairing-code:v1:{pairing}:" ‖
  device public key)`, first 4 bytes big-endian mod 10⁶, six digits.
- Argon2id parameters travel with the seal (`params: {alg, m, t, p,
  salt}`); clients refuse to open with less than 19 MiB of memory (a
  server cannot downgrade them to speed up an attack).
- Why AES-256-GCM rather than XChaCha20-Poly1305 (which the vault design
  anticipated): it is in WebCrypto, so the web app does everything except
  Argon2id natively and can keep keys non-extractable; random 96-bit
  nonces are safe at this scale (a vault seals thousands of secrets per key
  version, far below the 2³² bound, and every rotation starts again).
- **Shared vectors**: `core/crates/termoak-core/tests/e2ee_vectors.json`
  (user key, fingerprint, recovery key with its phrase and KEK, BIP39
  vectors and typed-phrase cases, both seals, a wrap, a
  secret, a pairing and its code, with the fixed nonces and ephemeral keys
  used). The core checks them both ways (`e2ee::tests::vectors`, plus RFC
  9180 A.1.1 for the HPKE schedule); `qa/lib/e2ee.mjs` is an independent
  WebCrypto implementation that passes them (Argon2id is given as its
  KEK: neither WebCrypto nor Node 22 has it) and drives the `e2ee` suite.

### 2.3 User keys

- One active X25519 key per user (`user_keys`, public key only), created
  by a client with a client-chosen id (it is in the seals' AAD). Setup
  requires a recovery seal; the passphrase seal is optional
  (`PUT /me/e2ee`). The apps show the recovery key once and ask the person
  to store it.
- On a device the private key is stored in the account store sealed with
  the device key (the keychain-protected key of every local store): a
  device is **unlocked** when it is there. `e2ee_lock` forgets it and the
  opened secrets of E2EE vaults (downloaded sealed again).
- Unlocking checks the opened key against the published public key
  (`e2ee_key_mismatch` otherwise: a server swapping keys).
- Changing the passphrase or getting a new recovery key replaces a seal
  (`PUT /me/e2ee/seals`); `DELETE /me/e2ee/passphrase` removes the
  passphrase seal.
- **Lost device**: sign it out (as today); optionally **rotate the user
  key** (`POST /me/e2ee/rotate`: a new key, its seals and a new wrap of
  every vault key the old one held, atomically). Managers can also rotate
  the vaults' keys.
- **Everything lost** (no device, no recovery key): `DELETE
  /me/e2ee?confirm=reset` forgets the key, its seals, pairings and wraps;
  without `confirm` it lists the vaults nobody else could open any more.
  The person sets E2EE up again and asks a key holder for new wraps.

### 2.4 Vault keys, members and rotation

- **Who may hold the key**: members whose role and team policy let them read
  secrets, i.e. Editors who may reveal and Admins (managers). Use-only and
  Connect-only members never get a wrap: in an E2EE vault they connect with
  team certificates (or through a key holder's per-session unlock) — there
  is no just-in-time credential the server could hand out.
- `Vault.e2ee` (only for `e2ee` clients) tells each member: `key_version`,
  `may_hold_key`, their `wrap` (for their current key), `rekey_needed`,
  `pending` (members who may hold it and have a key but no wrap; sent to
  key holders only) and `without_key` (count).
- **New members** (a grant, a team member of a team vault, someone who just
  set E2EE up, a promotion to Edit) appear in `pending`. A key holder
  **confirms** them: the app shows name, email and **fingerprint** and
  warns when this device wrapped for another key of theirs before (trust on
  first use, pins kept in the account store); then it wraps
  (`POST /vaults/{id}/e2ee/wraps`). Nothing is wrapped automatically, so a
  member injected by a malicious server is caught here.
- **Losing the right** (removal, downgrade below Edit, Forbid reveal, leaving
  the team, account deletion): the server stops serving their wrap at once
  and computes `rekey_needed` (a current-version wrap belongs to someone
  who may no longer hold the key). The next key holder online rotates
  (`POST /vaults/{id}/e2ee/rotate`, from the apps when they see the flag):
  a new VK (`version + 1`), every secret sealed again on the device, a wrap
  for every member who held the key and still may (others stay pending),
  `from_version` to detect races (`e2ee_stale`). Old key versions are
  deleted. What the removed member already downloaded stays theirs: the
  apps suggest changing those passwords.

### 2.5 Devices without the key (pairing)

1. The new device generates an ephemeral X25519 key and asks
   (`POST /me/e2ee/pairings {public_key}`); it shows the six-digit code.
2. The person's unlocked devices get the `e2ee`/`pairing` event, list the
   request (`GET /me/e2ee/pairings`) and show the code computed from the
   same public key.
3. If the codes match the person approves on the unlocked device: it seals
   its user key to the pairing key (`POST …/{id}/decide {approve, sealed}`).
   A device cannot approve itself; three pending pairings at most; ten
   minutes.
4. The new device fetches it once (`GET …/{id}`, then the server forgets
   the blob), opens it and checks it against the published key.

A server that swaps the new device's key makes the codes differ.

### 2.6 What the server does with an E2EE vault

| Feature | E2EE vault |
|---|---|
| Sync v2, REST of metadata | as usual; secrets travel as `sealed` (§2.8) |
| Reveal `GET /{col}/{id}/secret` | 409 `e2ee_locked` |
| Just-in-time credentials | 409 `e2ee_vault` (except hops that need no secret, e.g. team certificates) |
| Server sessions, host tests | work with a **per-session unlock** (`unlock` in `POST /sessions` and `POST /hosts/{id}/test`): the device resolves the host and sends that host's (and jumps') credentials, used for that connection only, then wiped; audited `e2ee.unlock`. Without it: 409 `e2ee_unlock_required` |
| `/exec`, SFTP through the server, network relays' server side | 409 `e2ee_unlock_required` when a hop needs a locked secret (per-session unlock for these is deferred, §12) |
| Server AI | hosts whose own secret is locked are left out of its inventory unless they sign in with a team certificate; a tool call that needs a locked secret fails with `e2ee_unlock_required`. The apps' local AI works (it runs on the unlocked device) |
| Team certificates | **work**: the CA is the server's; a hop without a usable secret gets the server's ephemeral key + certificate, so Connect-only and server-side use keep working. `POST /certificates` with a vault `key_id` still works (it only needs the key's public half, which is metadata, and the member's right to use it) |
| Access policies, approvals, recording policy | unchanged (they gate what the server serves, which now includes certificates and unlocked sessions) |
| Private networks | their secret stays server-sealed (legacy master-key format) even in an E2EE vault: the server must join the network. Shown as "readable by the server" (decision §9.3) |
| Recordings | not end-to-end encrypted (server sessions are seen by the server anyway; uploaded local recordings are plaintext) — decision §9.4 |
| Moves/copies between vaults with secrets | done by the clients (create sealed in the target, delete in the source); the server refuses with `e2ee_vault` |
| Session sharing | unchanged (a shared terminal never shares the vault) |

### 2.7 Turning E2EE on and off

- **On** (managers; `GET /vaults/{id}/e2ee` first, then `POST …/enable`):
  the device syncs, generates the VK for `next_version`, seals every item
  with a secret (the server checks the payload covers exactly
  `items`: `e2ee_incomplete` otherwise) and wraps the VK for itself and the
  members it confirms (`include`; the rest become pending). The server, in
  one transaction: reseals private network secrets to its legacy format,
  deletes its vault keys (crypto-shredded), stores the wraps and sealed
  secrets (new revision, same edit time, so an older offline edit still wins
  and is then re-sealed by its device), sets `crypto_mode = 'e2ee'`.
  Running server sessions keep running.
- **Off** (managers, `POST …/disable`): the device sends every secret in
  plaintext over TLS; the server seals them with a new server vault key and
  deletes the members' wraps. The vault reappears for old clients.

### 2.8 Protocol

- `SyncRecord.sealed: {key_version, blob_b64}` replaces `secret` for E2EE
  vaults. The server refuses plaintext (`e2ee_plaintext_rejected`), a stale
  version (`e2ee_key_outdated`, detail `key_version`) or a sealed secret for
  a server-managed vault (`e2ee_not_enabled`). A record without `secret`
  and `sealed` keeps the stored secret (as today). Rejected records stay
  dirty on the device and go again sealed with the current key.
- REST create/update accept `sealed` instead of `secret`.
- Records carry `e2ee_locked: true` when their secret is sealed for the
  reader (the server always; a device until unlocked).
- Clients (termoak-client): sync seals outgoing plaintext secrets of E2EE
  vaults with the VK from the vault list, holds back (dirty) changes of
  vaults it cannot open yet, opens incoming sealed secrets it can and stores
  the rest sealed (opened at unlock). Local connections to a host whose
  secret is still sealed fail with `e2ee_locked` ("Unlock").

### 2.9 Old clients

- `X-Termoak-Features: …,e2ee` (cores from v0.7.0-next.10) or
  `features=…,e2ee` on the events socket. Without it the server removes
  E2EE vaults from the caller's access for that request: vault lists, sync
  v2 (the authoritative list, so the local copy is wiped, with pending
  changes reported as discarded), entity routes (404) and pushes
  (`vault_not_found`). Turning E2EE on from such a client: 409
  `e2ee_client_required`.
- Legacy sync (`POST /sync`, cores before vaults) with an E2EE personal
  vault: 409 `e2ee_client_required` and nothing changes.
- Checked by the compat harness with the released apps (core v0.2.1) and
  the 0.4 next app (§8).

### 2.10 The web client (5b)

WebCrypto does X25519 (Chrome 133+, Firefox 130+, Safari 17+), HKDF and
AES-GCM; HPKE single-shot is ~60 lines on top (`qa/lib/e2ee.mjs` is the
reference). Argon2id needs a WASM build (hash-wasm or argon2-browser:
pinned and self-hosted). The unlocked user key is imported as a
**non-extractable** CryptoKey and kept in IndexedDB only with "Remember on
this browser", otherwise per tab. The served code is the weak point of web
E2EE (§2.1): the apps say so, and recommend the native apps for E2EE vaults.

### 2.11 Data model (migration v14)

`entities.e2ee` (the secret is a client's sealed blob), `user_key_seals`,
`e2ee_pairings`, an index on `user_keys`; `vault_key_wraps` (already there)
holds user wraps with `recipient = 'user:<id>'`, `alg =
'hpke-x25519-sha256-aes256gcm-v1'`, `recipient_key_id`. No vault changes
mode by the migration.

## 3. SSO / OIDC for teams

### 3.1 Settings

`team_sso.config` (`SsoConfig`, owners/admins, `PUT /teams/{id}/sso`):
`enabled`, `preset` (`google`, `microsoft`, `keycloak`, `authentik`,
`generic`), `issuer` (Google fills it; Microsoft builds it from `tenant`),
`client_id`, `scopes` (`openid email profile` + any), `email_claim`
(default `email`), `require_email_verified` (default on; Entra does not send
it), `enforce`, `owner_password_allowed` (default on), `auto_create`,
`auto_join` (default on), `satisfies_2fa`. The client secret is sealed with
the master key and never shown again (`has_client_secret`). Saving an
enabled config fetches the provider's discovery (issuer must match, every
endpoint must pass the egress rules). The redirect URI to register at the
provider is `<public_url>/api/v1/auth/sso/callback` (SSO needs
`public_url`; `/info features.sso`).

Egress (also for audit sinks): `https://` to public addresses only; private
addresses or plain `http://` only for prefixes in `[sso]
allowed_issuers`; names resolve to public addresses only; no redirects.

### 3.2 Verified domains

`POST /teams/{id}/domains {domain}` returns a token; the team publishes
`TXT _termoak-challenge.<domain> "termoak-verify=<token>"` and asks
`POST …/verify` (DNS through the system resolver or `[sso] dns_servers`).
A domain verified by one team, or claimed by it less than a week ago,
cannot be claimed by another (`sso_domain_taken`). A server administrator
can vouch for a domain without DNS (`POST
/admin/teams/{id}/domains/{d}/verify`, internal domains). Enforcement
needs a verified domain; removing the last one turns enforcement off.

### 3.3 The flow

```
app ──POST /auth/sso/start {email|team_id, redirect_uri, state, code_challenge}──▶ server
app ◀── {authorize_url} (server state, nonce, its own PKCE towards the IdP) ──── server
app ──opens authorize_url in the system browser──▶ IdP ──user signs in──┐
server ◀── GET /auth/sso/callback?code&state ─────────────────────────────┘
server ──code + PKCE verifier (+ client secret)──▶ IdP token endpoint ──▶ ID token
server: checks signature (JWKS, refreshed once for an unknown kid), iss, aud/azp,
        exp/iat (±2 min), nonce, sub, email (+ email_verified, Google hd)
browser ◀── 303 redirect_uri?code=<one-time>&state=<app state> ── server
app ──POST /auth/sso/exchange {code, code_verifier[, totp_code]}──▶ server ──▶ tokens
```

The one-time code is stored hashed, works once (or again after a
`totp_required`), dies after ten minutes and five wrong verifiers. The
app's PKCE means a code intercepted on its way to a custom scheme is
useless without the verifier.

### 3.4 How each app signs in

| App | Browser | Callback |
|---|---|---|
| Desktop, CLI | the system browser | loopback `http://127.0.0.1:<random port>/callback` (RFC 8252 §7.3): `SsoLoopback` in the FFI / `sso::Loopback` in termoak-client answers "you can close this window" |
| Android | Custom Tab | `termoak://sso` (intent filter on the scheme, RFC 8252 §7.1) |
| iOS | `ASWebAuthenticationSession` (callback scheme `termoak`) | `termoak://sso` |
| Web | the same tab | `<public_url>/app/sso` (same origin) |

Allowed redirect URIs: loopback on any port, `termoak://sso…`, and the
server's own `/app/sso…`. Universal/App Links are not used: self-hosted
servers cannot vouch for the apps' domains.

### 3.5 Accounts

1. An identity already linked (`sso_identities`: issuer + subject) signs in
   its account.
2. Otherwise, if the email's domain is **verified by this team**: the
   account with that email is linked (the team proved it controls the
   domain's mailboxes), or one is created (`auto_create`: verified email,
   `sso_only`, no usable password).
3. Otherwise `sso_account_not_linked`: the person signs in normally and links
   their identity (`POST /me/sso/link`, then the same flow; the identity must
   not belong to another account). `DELETE /me/sso/{team}` unlinks (refused
   for `sso_only` accounts).
4. `auto_join` adds the person to the team (member).

### 3.6 Enforcement

With `enforce` and a verified domain: password sign-in, sign-up and
password reset of that domain answer 403 `sso_required` (`team_id`,
`team_name`), audited `auth.login_refused`. Exempt: server administrators
and, with `owner_password_allowed`, the team's owner (break glass when the
provider is down). Tokens issued before stay valid until they expire (sign
everyone out from Devices if needed). Old apps show the message ("Corp signs
in through single sign-on").

### 3.7 Two-step verification

- `satisfies_2fa` (the team says its provider enforces MFA): an SSO sign-in
  through that team does not ask the account's own TOTP, and the team's
  "require 2FA" policy counts linked identities as compliant (vault access,
  `team_2fa`, compliance list `sso_2fa`).
- Otherwise an account with TOTP is asked for its code at the exchange
  (`totp_required`, then the same code with `totp_code`).

### 3.8 SSO and E2EE

An identity provider cannot give a key, and the server must never derive
one. SSO users set up E2EE like everyone (recovery key, optional
passphrase) and unlock new devices with it or by pairing. Escrow to team
admins is a possible later option (§9.2).

## 4. Extended audit

### 4.1 Team scope

`audit_log.team_id`: entries of team vaults (from the vault's owner team)
and entries whose target is a team (CA, policy, members, SSO, sinks), and
explicit team entries (`audit_team`). The migration backfills both.

### 4.2 Search

`GET /audit` (your account), `/vaults/{id}/audit` (managers),
`/teams/{id}/audit` (owners, admins), `/admin/audit` (administrators), all
with `action` (comma list, `access.*` prefixes), `actor` (user id or actor
string), `vault_id`, `target`, `since`/`until` (ms), `q` (text in action,
actor, target, details), `before` (newest first) or `after` (oldest first),
`limit` (≤ 1000). Old clients' `before`/`limit` behave as before.

### 4.3 Export

`…/audit/export?format=csv|json|ndjson&<filters>`: streamed, oldest first,
at most `[audit] max_export_rows` (100 000), audited `audit.export` in its
scope. CSV columns `id,time,action,actor,owner_id,team_id,vault_id,target,
detail` (RFC 4180; cells starting with `= + - @` get a `'`). JSON/NDJSON
use the SIEM event shape: `{id, time (RFC 3339 UTC, ms), created_at,
action, actor, owner_id, team_id, vault_id, target, detail, server}`.

### 4.4 Retention

`[audit] retention_days` (365; 0 keeps everything) for entries without a
team setting; a team sets its own (`PUT /teams/{id}/audit/settings
{retention_days}`, 1 to `max_team_retention_days`, 3650). An hourly job
deletes what is older.

### 4.5 Sinks

Per team (owners/admins, up to `max_sinks_per_team`) or server-wide
(administrators): `{kind, name, config, actions}`.

- **Webhook**: `POST` of `{sink_id, server, events: [...]}` (up to 100) with
  `X-Termoak-Timestamp`, `X-Termoak-Event-Id: <first>-<last>` and
  `X-Termoak-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>`;
  2xx = delivered. The secret (`whsec_…`) is shown once at creation.
- **Syslog**: RFC 5424 `<PRI>1 TIMESTAMP HOSTNAME termoak - <action>
  [termoak@32473 id actor team vault target] BOM<event JSON>`; facility 13
  (log audit) by default; severity warning for `*_failed`, `*.deny`,
  `*.revoke`, notice for configuration (`sso.config`, `e2ee.*`,
  `team.policy`, `ca.*`, `audit.*`), informational otherwise; over TLS
  (default port 6514, public roots or the sink's `ca_pem`) or TCP (only to
  allowed targets), RFC 6587 octet counting.
- Delivery: a job every 5 s reads entries after each sink's cursor (its
  scope, 100 at a time), sends the ones matching its actions and moves the
  cursor on success: in order, at least once, across restarts. Failures
  back off (5 s doubling to 10 min) and show `failures`/`last_error`.
  `POST …/{sink}/test` sends a synthetic `audit.test` now. A new sink starts
  at the newest entry.
- SSRF: the same egress rules as SSO (`[audit] allowed_targets` for private
  or plain targets, `syslog://host:port` for syslog).

### 4.6 Actions

Existing `auth.*`, `vault.*`, `secret.*`, `session.*`, `access.*`,
`access_policy.*`, `cert.*`, `ca.*`, `team.*`… plus:
`e2ee.setup|seal|passphrase_removed|key_rotate|reset|pairing_request|
pairing_approve|pairing_deny|enable|rotate|disable|wraps_add|unlock`,
`sso.config|domain_add|domain_verify|domain_check_failed|domain_remove|
login|login_failed|link|unlink|user_created`, `auth.login_refused`,
`audit.export|settings|sink_create|sink_update|sink_delete`.

## 5. Core and FFI surface

- `termoak_core::e2ee` (crypto, §2.2), `termoak_core::sso` (config,
  presets, domains, PKCE, allowed redirects), `store::e2ee`, `store::sso`,
  `store::audit` (filters, sinks, retention), `resolve::E2eeUnlock` and
  `Store::resolve_in_with`, `ResolvedHost.e2ee_locked`, `RecordMeta.
  e2ee_locked`, `Vault.e2ee`, `User.sso_only`, `AuditEntry.team_id`.
- termoak-client: `e2ee` (device key storage, sync sealing/opening, setup,
  unlock, pairing, enable/rotate/disable, pending members with TOFU pins,
  `e2ee_unlock_for`), `sso` (start, callback, exchange, loopback),
  `audit` (search, export, settings, sinks); `Workspace::sso_start/
  sso_complete`; `SyncReport.e2ee_waiting/e2ee_locked`.
- FFI (`TermoakCore` and `AccountHandle`): `e2ee_status`, `e2ee_setup`,
  `e2ee_unlock_with_passphrase`, `e2ee_unlock_with_recovery_key`,
  `e2ee_lock`, `e2ee_set_passphrase`, `e2ee_new_recovery_key`,
  `e2ee_pairing_start/finish`, `e2ee_pairings`, `e2ee_pairing_decide`,
  `e2ee_vault_state`, `e2ee_enable_vault`, `e2ee_disable_vault`,
  `e2ee_rotate_vault`, `e2ee_pending_members`, `e2ee_add_members`,
  `open_server_session_unlocked`; `sso_discover`, `sso_start`,
  `sso_complete`, `sso_start_loopback` → `SsoLoopback.flow()/
  wait_callback()`, `team_sso`, `set_team_sso`, `delete_team_sso`,
  `team_domains`, `add_team_domain`, `verify_team_domain`,
  `remove_team_domain`; `audit_search`, `audit_export`,
  `team_audit_retention`, `set_team_audit_retention`, `audit_sinks`,
  `create_audit_sink`, `update_audit_sink`, `delete_audit_sink`,
  `test_audit_sink`; pure `e2ee_fingerprint`, `e2ee_recovery_key_valid`,
  `e2ee_recovery_key_check` (reason and word of a refusal) and
  `e2ee_recovery_wordlist` (v0.7.0-next.11); `e2ee_remove_passphrase`,
  `e2ee_rotate_user_key(passphrase?)` (new key, every vault key wrapped
  again, a new recovery phrase returned) and `e2ee_reset(confirm)` (the
  vaults that would be lost without `confirm`; locks this device after it)
  (v0.7.0-next.12); `test_host_unlocked(host_id, trust)` (a server host
  test with the per-test unlock, the server's answer as JSON; v0.7.0-next.13,
  for the phones). Since v0.7.0-next.12 the client also moves and copies
  items into and out of E2EE vaults on the device (`transfer` →
  `transfer_between` when a source or the target is E2EE, sealed for the
  target), and `export_local` refuses E2EE secrets with `e2ee_locked`.
  Records: `VaultInfo.e2ee`, `SshHost/SshIdentity/SshKey.e2ee_locked`,
  `SyncReport.e2ee_waiting/e2ee_locked`, `AuditEvent.vault_id/team_id`.
  Errors: `TermoakError.E2eeLocked` (`e2ee_locked`,
  `e2ee_unlock_required`) and `SsoRequired`.

## 6. API summary

| Method | Route | Who |
|---|---|---|
| GET, PUT, DELETE | `/me/e2ee` | the user (DELETE `?confirm=reset`) |
| PUT | `/me/e2ee/seals` · DELETE `/me/e2ee/passphrase` · POST `/me/e2ee/rotate` | the user |
| GET, POST | `/me/e2ee/pairings` · GET `/me/e2ee/pairings/{id}` · POST `…/{id}/decide` | the user's devices |
| GET | `/vaults/{id}/e2ee` | key holders |
| POST | `/vaults/{id}/e2ee/enable` · `/disable` | managers |
| POST | `/vaults/{id}/e2ee/rotate` · `/wraps` | key holders |
| GET | `/auth/sso/discover?email=` · POST `/auth/sso/start` · GET `/auth/sso/callback` · POST `/auth/sso/exchange` | public |
| GET · POST · DELETE | `/me/sso` · `/me/sso/link` · `/me/sso/{team_id}` | the user |
| GET, PUT, DELETE | `/teams/{id}/sso` | members read (no secrets), owners/admins |
| GET, POST · POST · DELETE | `/teams/{id}/domains` · `…/{domain}/verify` · `…/{domain}` | owners/admins |
| POST | `/admin/teams/{id}/domains/{domain}/verify` | administrators |
| GET | `/audit`, `/vaults/{id}/audit`, `/teams/{id}/audit`, `/admin/audit` (+ `/export`) | per scope |
| GET, PUT | `/teams/{id}/audit/settings` | owners/admins |
| GET, POST · PATCH, DELETE · POST | `/teams/{id}/audit/sinks` · `…/{sink}` · `…/{sink}/test` (and `/admin/audit/sinks…`) | owners/admins (administrators) |

Also: `unlock` in `POST /sessions` and `POST /hosts/{id}/test`; `sealed` in
sync v2 and REST; `Vault.e2ee`; `/info features.e2ee`, `features.sso`,
`features.audit_v2 {filters, export, retention, sinks}`; events
`{"type":"e2ee","event":"pairing","pairing":{…}}`.

New error codes: `e2ee_locked`, `e2ee_unlock_required`, `e2ee_vault`,
`e2ee_plaintext_rejected`, `e2ee_key_outdated`, `e2ee_not_enabled`,
`e2ee_already_enabled`, `e2ee_incomplete`, `e2ee_stale`,
`e2ee_wrap_invalid`, `e2ee_not_set_up`, `e2ee_key_exists`,
`e2ee_key_mismatch`, `e2ee_client_required`, `e2ee_pairing_closed`,
`e2ee_passphrase_invalid`, `e2ee_passphrase_too_short`,
`e2ee_recovery_key_invalid`, `e2ee_decrypt_failed` (the last four also on
the device); `sso_required`, `sso_not_configured`, `sso_issuer_invalid`,
`sso_redirect_invalid`, `sso_pkce_invalid`, `sso_state_invalid`,
`sso_code_invalid`, `sso_failed`, `sso_email_missing`,
`sso_email_unverified`, `sso_account_not_found`, `sso_account_not_linked`,
`sso_identity_taken`, `sso_domain_taken`, `sso_domain_unverified`,
`sso_only_account`; `audit_sink_invalid`, `invalid_format`,
`invalid_retention`.

Configuration: `[sso] enabled, allowed_issuers, dns_servers, timeout_secs`
and `[audit] retention_days, max_team_retention_days, max_export_rows,
max_sinks_per_team, allowed_targets`.

## 7. Compatibility

- Nothing changes until a manager turns E2EE on or a team saves SSO
  settings; the migration only adds columns/tables and backfills
  `audit_log.team_id`.
- Old clients: §2.9; SSO enforcement reaches them as an error with a
  readable message; the audit listings keep their array shape and
  parameters.
- Old servers: the new core asks `/info features.e2ee|sso|audit_v2` before
  calling the new endpoints; without them the apps hide the UI; the
  `e2ee` feature in the header is ignored by older servers.
- The session holder needs nothing new: a per-session unlock arrives in the
  `ResolvedHost` it already receives.

## 8. Tests

- Core: RFC 9180 A.1.1, round trips and tampering, cheap-parameter
  passphrase seals and downgrade refusal, the shared vectors both ways;
  store: enable → server-side lock → per-session unlock → sync to holders /
  non-holders → old-client view → rekey after a downgrade → wraps for
  pending members → disable; pairing; migration v14; audit filters, team
  scope, sinks' cursors, retention; SSO domains, flows (state once, code
  once, PKCE), identities, SSO counting as 2FA. termoak-client: callbacks,
  loopback, audit query strings. FFI: helpers and error variants.
- Server: `tests/e2ee.rs` (lifecycle with the core's crypto as client,
  per-session unlock against a real sshd, pairing, reset, legacy sync),
  `tests/sso.rs` (an in-process OpenID provider with ES256 keys and a DNS
  server: domain proof, enforcement, accounts created and linked, tampered
  tokens, unverified emails, redirects, linking, 2FA interplay, private
  issuers), `tests/audit.rs` (filters, exports, retention, webhook HMAC,
  syslog TCP and TLS with a private CA, failures and backoff),
  `tests/ffi_e2ee_sso_e2e.rs` (the apps' engine: three devices, recovery
  key, pairing, an unlocked server session, SSO through the loopback and
  the mobile callback, audit through the FFI).
- QA: `e2ee` (vectors in WebCrypto; a vault through lib/e2ee.mjs; pairing;
  per-session unlock with the QA sshd), `sso` (Dex in Docker, DNS proof,
  enforcement, accounts, PKCE), `audit` (filters, exports, retention,
  webhook, syslog TCP and TLS), compat section (§2.9, SSO errors in the old
  apps, audit listings).

## 9. Decisions for the owner

Decided by the owner on 2026-10-27 (before phase 5b):

1. **Metadata stays readable** by the server in E2EE vaults (labels,
   addresses, usernames, notes): only secrets are end-to-end encrypted,
   as implemented. Encrypting metadata would remove search, the server's
   views of hosts and server-side features for those vaults. Possible
   later: an "encrypted notes" field. — **Accepted.**
2. **No key escrow**: losing every device and the recovery key loses the
   vault keys the person alone held. Possible later: a team recovery key
   (wraps for team admins) for team vaults. — **Accepted (default).**
3. **Private network secrets** in an E2EE vault stay readable by the server
   (it joins the network). Networks are allowed in E2EE vaults, as
   implemented, and the apps show a clear warning that the network's key is
   readable by the server (the network editor and the vault's encryption
   settings). — **Accepted.**
4. **Recordings are not end-to-end encrypted** (managers play them in the
   web too). Possible later: seal uploaded recordings with the VK. —
   **Accepted (default).**
5. **Recovery key format**: changed to a **24-word English BIP39 phrase**
   (256 bits of entropy + the BIP39 checksum; §2.2) instead of 56 base32
   characters. Done first, in core v0.7.0-next.11 (generation, parsing
   tolerant of case/whitespace/numbering with four-letter prefixes,
   `detail.reason` for the refusals, vectors, FFI `e2ee_recovery_key_check`
   and `e2ee_recovery_wordlist`). No account used the first format (staging
   was clean), so there is no migration: the old format is refused with
   `old_format`. — **Changed.**
6. **Break glass**: the team owner (and server administrators) keep
   password sign-in under enforcement by default; teams can turn the
   owner's off. — **Accepted (default).**
7. **Syslog structured-data id** `termoak@32473` keeps the documentation
   enterprise number (RFC 5612) as a placeholder; registering a Private
   Enterprise Number with IANA (free) would make it `termoak@<PEN>`. —
   **Accepted (placeholder).**
8. **Plans**: SSO, E2EE and audit sinks are included in **every plan, Free
   included**. Checked in phase 5b: the server gates none of them by plan
   (plan limits are only teams, team members, server sessions, networks
   and the server AI; `[audit] max_sinks_per_team` is a server setting for
   every team). — **Decided: every plan.**

## 10. Checklist 5b — web + desktop (done 2026-10-27)

Desktop 0.7.0-next.5 (desktop `next` 013f82d, core v0.7.0-next.12) and the
web (web `next` ec828e1), server 0.7.0-next.11 on staging (CSP allows
WebAssembly, `/me/sso` names the team). QA: browser suites `e2ee`, `sso`,
`audit` (qa `main` 55666f7).

- [x] Features: the desktop gets `e2ee` from the core; the web declares
      `e2ee` (header wrapper and events socket) since it implements §2.
- [x] Account → Security → End-to-end encryption: set up (24 words shown
      once, numbered, with copy/save/print, then three of them asked back;
      nothing is published before that; optional passphrase with a strength
      hint), status (fingerprint, unlocked here or not), unlock (passphrase /
      recovery phrase with live feedback by reason / another device with the
      six-digit code), lock, change/remove passphrase, new recovery phrase,
      replace the key, reset (typed confirmation, with the vaults that would
      be lost). Desktop: Settings has its own Security and Activity pages.
- [x] Pairing requests: banner/toast, sidebar badge (web), the code,
      Approve/Deny (desktop: also a system notification when in the
      background).
- [x] Vault → Encryption: turn on (who gets the key now with fingerprints,
      unchecked members wait; what changes; the network warning, §9.3),
      turn off (typed name), rotate; `rekey_needed` banner; pending members
      with fingerprints and the key-changed warning, Confirm. The desktop
      also rotates by itself, once per vault and version, when it holds the
      key and the server flags `rekey_needed` (a toast says so).
- [x] Lock badges on E2EE vaults and items, "Unlock" on `E2eeLocked`,
      `SyncReport.e2ee_waiting/e2ee_locked` notices; the terminal shows a
      locked card with Unlock.
- [x] Server sessions/tests on E2EE hosts: "Send this host's credentials for
      this session?" → `unlock` (desktop through the core's
      `unlock_payload`, web resolving the same chain: jumps, identity, key,
      proxy password).
- [x] Moves/copies with E2EE: done on the desktop (core v0.7.0-next.12
      `transfer_between`). The web has no move/copy UI, so nothing to add;
      it refuses key import into an E2EE vault (the server cannot read it).
- [x] Web crypto: WebCrypto HPKE, X25519 in JavaScript where WebCrypto lacks
      it (Chrome < 133, Safari < 17; "Remember on this browser" hidden
      there), Argon2id with hash-wasm's WebAssembly (pinned by SHA-256) or a
      JavaScript fallback; every vector of `e2ee_vectors.json` passes with
      both. The key is a non-extractable CryptoKey in IndexedDB only with
      "Remember". A warning wherever keys are handled: the served code is
      the weak point, prefer the native apps.
- [x] Sign-in: the email asks `GET /auth/sso/discover` ("Continue with
      <team>", only that when enforced, the owner's password as break
      glass); desktop loopback + system browser (PKCE) + TOTP step; web
      `/app/sso`; `sso_required` switches to SSO.
- [x] Team → Single sign-on with the five presets and their steps, redirect
      URI to copy, write-only secret, domains with the TXT record to copy
      (desktop also as a zone-file line), Verify, enforce (needs a verified
      domain), auto-create/join, "SSO counts as 2FA"; linked identities
      (link/unlink).
- [x] Audit: team, account (and vault on the web) views with presets
      (Access, Certificates, Policy, E2EE, SSO, Sign-ins), person, dates,
      text, load more / endless scrolling (`before`), export CSV/JSON/NDJSON;
      team retention; sinks (webhook with the secret once, syslog over TLS
      or TCP, test, state with failures and last error, pause, delete); the
      web also has the server-wide sinks in Administration.
- [x] en/es texts for every new error code, recovery reason and audit
      action.

Checked on staging with two accounts (desktop in Xvfb with a second
device and the other member played by the core, and the web with two
browsers): setup, phrase confirmation (prefixes and capitals accepted),
vault turned on with fingerprints, a member left waiting and confirmed from
the banner, local SSH with an E2EE key, pairing with matching codes, server
host test and server session with per-connection unlock, lock and unlock
with the phrase (typo explained), automatic rotation after a downgrade,
team SSO with a local Dex (temporary `allowed_issuers`, restored),
domain verification failure then administrator vouching, enforcement,
identity link through the system browser, an SSO-created account, team
audit with presets, retention, a webhook sink delivered and tested, export,
items copied out of the E2EE vault on the device, E2EE turned off.

Findings:
- The server's CSP blocked WebAssembly, so the web ran Argon2id in
  JavaScript (~3 s per unlock instead of ~0.3 s): server 0.7.0-next.11 adds
  `'wasm-unsafe-eval'` to `script-src` (compilation only, no `eval`).
- `/me/sso` now includes `team_name` (the web looked it up from `/teams`).
- Server-side moves out of or into E2EE vaults are refused (5a); the core
  now does them on the device (v0.7.0-next.12) and refuses exporting
  sealed secrets in plain text.
- `rekey_needed` reaches the other holders with the periodic sync (about
  five minutes on the desktop) unless an event arrives first; rotation is
  automatic on the desktop and offered by a banner on the web.
- File dialogs (export, save the phrase) and system notifications cannot be
  exercised under Xvfb without a portal; checked through the client calls.
- QA Chromium 130 has no WebCrypto X25519: the browser suites cover the
  JavaScript X25519 path, Node tests the native one.

## 11. Checklist 5c — Android + iOS (done 2026-10-27)

Android 0.7.0-next.6 (mobile-android `next` 23a916e) and iOS (mobile-ios
`next` 2e08ebe, not built on a Mac here), both on core v0.7.0-next.13 (one
call added: `test_host_unlocked`); server unchanged (staging 0.7.0-next.11).

- [x] Core bindings: `TermoakError.E2eeLocked/SsoRequired` read by code
      (`e2ee_recovery_key_invalid` with `detail.reason` and `word`,
      `sso_required` with `team_name`), `VaultInfo.e2ee`, `e2ee_locked` on
      hosts, `SyncReport.e2ee_waiting`, `AuditEvent`. The core declares
      `e2ee` (header and events socket) since next.10, so the apps declare it
      together with this phase.
- [x] Setup like the desktop: the 24 words numbered in two columns, copy
      (sensitive on Android, this device only and two minutes on iOS), save
      (Android: the system's document picker; iOS: Files), print (the
      system's print service), three words asked back; live feedback from
      `e2ee_recovery_key_check`, suggestions from `e2ee_recovery_wordlist`.
      The phrase screen is `FLAG_SECURE` on Android (a secure full-screen
      dialog: no screenshots, recordings or app-switcher thumbnail); iOS
      hides the words while the app is not active or the screen is captured
      (recorded/mirrored), so the app switcher's snapshot never has them.
- [x] Unlock with passphrase / recovery phrase / pairing (new device polls
      every 3 s; the approving device gets the `e2ee` event, also re-read on
      `hello`, and shows the same code: a dialog in front, a notification
      of the app's own in the background, since the server sends no push for
      pairings), lock, change/remove passphrase, new recovery phrase, replace
      the key, reset (`e2ee_reset(false)` first, typed email). New phrase,
      replace and reset behind the screen lock (BiometricPrompt / Face ID).
      The key stays in the engine's account store sealed with the
      Keystore/Keychain-protected device key.
- [x] E2EE vaults: badges (locked when this device can't open it), Locked
      chip on hosts, Home banners (locked, a device asking, members waiting,
      set up to get a key), Vault → Encryption (turn on with fingerprints,
      unchecked members wait, what changes, networks warning; confirm
      pending members with the key-changed warning; rotate; turn off with
      the typed name), automatic rotation on `rekey_needed` after a sync
      (once per vault and version), the networks warning in the network
      form. Terminals: a locked host shows Unlock and connects again; a
      server session asks "Send this host's credentials for this session?"
      (`open_server_session_unlocked`); a server host test asks too
      (`test_host_unlocked`, new in core next.13).
- [x] Moves/copies through the core's `transfer` (client-side for E2EE);
      sealed exports refused with `e2ee_locked` in words.
- [x] SSO: Android Custom Tab (androidx.browser) + intent filter
      `termoak://sso`; iOS `ASWebAuthenticationSession` with
      `callbackURLScheme: "termoak"`; `sso_discover` on the email step
      ("Continue with <team>", only that when enforced, the owner's
      break-glass password behind a link), `sso_start`, `sso_complete` with
      the callback (+ TOTP step); `sso_required` on sign-in or sign-up
      switches to SSO.
- [x] Team SSO and domains (presets with their steps, redirect URI to copy,
      write-only secret, rules, TXT record as name/value/zone line to copy
      or share, verify, remove, enforce only with a verified domain), linked
      identities (link with the app's own PKCE through `POST /me/sso/link`,
      unlink).
- [x] Audit: account (Settings → Security), team (owners/admins) and vault
      (Admins, servers with `audit_v2`) with the desktop's presets, ranges,
      text, person, load more; export CSV/JSON/NDJSON to the share sheet;
      team retention (`GET /teams/{id}/audit/settings` for the default and
      maximum); sinks: state, test, pause/resume, delete (creation stays on
      the desktop and the web).
- [x] en/es for every new code, recovery reason and audit action (the
      desktop's 5b texts with "this computer" as "this device", plus the
      apps' own: Android `strings_e2ee_sso_audit.xml`, iOS
      `Localizable.xcstrings`).

Checked: Android JVM tests 414 (58 opt-in skipped), including the shared
`e2ee_vectors.json` and BIP39 vectors through the engine built for this
computer (`E2eeVectorsTest`), screenshots of 20 screens in en/es ×
light/dark, debug build; an opt-in `LiveE2eeTest` against staging with the
same engine: setup, a shared E2EE vault confirmed by fingerprint, reveal
refused, host test and server session refused then unlocked per connection
against an OpenSSH container (host key trusted with the unlocked test),
local SSH with the sealed key, a second device unlocked by pairing (same
code) and again with the recovery phrase typed as numbered four-letter
capitals, automatic rotation after a downgrade, the vault audit and its
CSV export, SSO through a local Dex (temporary `[sso] allowed_issuers`,
restored): an account created through `termoak://sso`, an identity linked
and unlinked, enforcement refusing a password sign-in with the team named;
E2EE turned off; everything removed. iOS: 187 XCTests on Linux (the pure
rules, PKCE vector, the shared fingerprint and pairing-code vectors), the
new and changed files type-check against the stand-in modules (only the
stubs' gaps).

Findings:
- The FFI had no way to test an E2EE host from the server with the
  per-test unlock (the desktop builds it in termoak-client): core
  v0.7.0-next.13 adds `test_host_unlocked`. A host test is also what trusts
  a new host key, so a host added straight into an E2EE vault needs it.
- Linking an identity needs the account to be a member of the team
  (`not_team_member` otherwise); the identity's email domain does not need
  to be verified.
- The server sends no push for pairing requests: the phones learn them
  from the events socket (and `hello`), so a phone that is fully closed
  sees them on the next start; the other device keeps polling for ten
  minutes.
- As on the desktop, `e2ee_setup` publishes the key before the three words
  are confirmed; the apps warn when closing before confirming (the phrase
  is never shown again; a new one can be made from Security).
- An SSO-made account (`sso_only`) can't be deleted by an administrator
  directly: to clean up, the administrator sets a password and the account
  deletes itself after its team (and its enforcement) is gone.

## 12. Deferred / open

- Per-session unlock for `/exec`, server SFTP and the AI pool (today: team
  certificates or the device's own connections).
- Team recovery key / escrow (§9.2); encrypted notes (§9.1); E2EE
  recordings (§9.4).
- SCIM, SAML, server-wide SSO (not per team), IdP-initiated sign-in, back-
  channel logout; SSO-bound short certificates (TEAMS-SECURITY §14).
- Syslog over UDP, sinks for Splunk HEC / Elastic / Datadog (webhooks cover
  most), signed audit exports.
