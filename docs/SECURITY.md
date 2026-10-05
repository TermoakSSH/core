# Security

To report a vulnerability, please do not open a public issue: contact Ohz
Digital SL through https://termoak.com.

## Secrets

- **Encryption.** Passwords, private keys, passphrases and other secrets are
  stored with **XChaCha20-Poly1305**, with a random 24-byte nonce and a
  version byte. The AAD, `termoak:{kind}:{id}`, binds each secret to its
  record: the ciphertext of one host cannot be copied to another.
- **Server master key.** Taken from `TERMOAK_MASTER_KEY` (base64) or,
  if unset, from `<data_dir>/master.key`, which is created with `0600`
  permissions. **Back up that key**: without it, the stored secrets cannot
  be recovered.
- **Vault key on clients.** Looked up in this order:
  1. `TERMOAK_VAULT_KEY`.
  2. The system keychain: Keychain, Credential Manager or Secret Service.
  3. The `vault.key` file (`0600`) in the data directory.
- **This device only.** Any entity or secret can be marked this way and
  never leaves the device: it is not synced and the server never sees it.
- **Revealing secrets.** The API never returns secrets in listings. They
  must be requested explicitly (`GET /{collection}/{id}/secret`), and the
  request is audited.
- **In memory.** Resolved types (`ResolvedHost`, `ResolvedKey`) hide secrets
  in their `Debug` output. The master key and serialized secrets are zeroed
  when dropped (`zeroize`).

## Accounts

- **Passwords.** Argon2id. If the user does not exist, the login still
  verifies a dummy hash, so the response time does not reveal which emails
  exist.
- **Tokens.** Each device has a 60-minute access token and a 90-day refresh
  token. The database only stores their SHA-256. Refreshing rotates both.
  Signing a device out invalidates it immediately.
- **Registration.** By default it is `first_user`: only the first user can
  sign up, and becomes an administrator. After that, accounts are created by
  an administrator or sign up with an **invitation**: a random, single-use
  token (only its hash is stored) that expires (7 days by default) and can be
  bound to an email.
- **Two-step verification.** TOTP (RFC 6238, SHA-1, 6 digits, 30 s) with a
  window of ±1 step. Each code is accepted only once (the last used step is
  stored). The secret is encrypted with the master key. There are 10
  single-use recovery codes, of which only the SHA-256 is stored. Disabling
  it asks for the password and a code; an administrator can remove it if the
  user loses their phone.
- **Rate limiting.** Sign-in is blocked for 10 minutes after 10 failures for
  the same email or 30 from the same IP. Behind Caddy or nginx, enable
  `trust_forwarded_for` so the IP is the client's (the last one in
  `X-Forwarded-For`, added by your proxy). Do not enable it if the server is
  exposed directly: anyone could forge the header.
- **Emails with links.** Verifying the email (48 h), resetting the password
  (1 h) and confirming an email change use random single-use tokens of which
  only the SHA-256 is stored; asking for a new one invalidates the previous
  one. A password reset request gets the same answer whether the account
  exists or not, counts as an attempt for the per-email and per-IP limits,
  and using it signs out every device (two-step verification is still
  required).
- **Email verification codes.** When the server requires a verified email,
  the verification email also carries a six-digit code (from the system
  generator) that verifies the email and signs in. It lasts 15 minutes, a
  new one replaces the previous one, and five wrong tries use it up. Only an
  HMAC-SHA256 of it, keyed with the server's master key and salted, is
  stored, so a copy of the database alone does not reveal it. Wrong codes
  count as failures for the sign-in limits (per email and per IP), the
  answer is the same whether the account exists or not, and code emails are
  limited to one a minute and five an hour per address (thirty an hour per
  IP).
- **Deleting the account.** Asks for the password and, if enabled, a
  verification code. Deletes the vault records, the sessions and their
  history, the recordings, the AI tasks, the user's own audit entries and
  the teams where the user was the only member. It is not allowed if it
  would leave a team without an owner or the server without administrators.
- **Teams.** Sharing a session with a team gives access to its current
  members: whoever leaves the team is kicked out at once from the sessions
  shared with it, unless they have another share.

## Web app

- **Strict CSP**: only the server's own resources, no inline scripts or
  styles and no frames (`frame-ancestors 'none'`). The web app builds the
  page with `textContent`, never with HTML from the API.
- **`Referrer-Policy: no-referrer`**, so the tokens in email links don't leak
  to other sites.
- The web app's session tokens are kept in the browser (`localStorage`) and
  renewed like in the apps; signing out revokes the device.

## Push notifications

- The text is **generic by default** (Apple and Google see it). With
  `[push] detailed = true` it includes commands and titles.
- Each phone's token is bound to its device: when the device signs out or is
  revoked it stops getting notices, and if APNs or FCM report the token as
  invalid, it is forgotten.
- The APNs and FCM keys can only send notifications; keep them out of the
  repository (a file with restricted permissions or an environment
  variable).

## SSH

- **Known hosts.** TOFU applies. If the fingerprint changes, the connection
  is **always refused**. On the server, the policy is set with
  `host_key_policy`:
  - `ask`: asks the owner over WebSocket.
  - `accept_new`: accepts new hosts automatically.
  - `strict`: only accepts hosts already known.
- **Agent forwarding.** Disabled unless enabled per host.
- **Recording.** Disabled by default. Keyboard input is never recorded
  unless `record_input = true`, because it can contain passwords.

## Shared sessions

- **Link tokens.** Random, 256-bit; only their hash is stored. They can
  expire.
- **Permissions.** Two levels: `view` (watch only) and `control` (can ask
  for the keyboard). One person types at a time: the owner always can,
  everyone else only while the owner lets them (or automatically, with
  `auto_grant`). Input and resizes from anyone else are dropped on the
  server. Only the owner answers connection prompts (known host, 2FA) and
  closes the session.
- **Waiting room.** Links ask the owner before letting anyone in (by
  default); the owner can say no or kick someone out (and revoke their
  share).
- **Revocation and expiry.** Revoking or expiring a share sends away whoever
  joined with it at once, unless they have another valid share; so does
  deleting or disabling an account.
- **Privacy.** Only the owner sees user ids and share ids; the public link
  page only says how many people are inside. Link guests choose a display
  name (cleaned of control and direction characters, 40 characters at most).
- **Audit.** Joins (also of link guests, with their name; once per person,
  not per reconnect), leaves, waiting room decisions, keyboard changes,
  kicks, share changes and "stop sharing" are logged.

## AI

- **Permissions.** See [AI.md](AI.md). By default the AI only reads; changes
  wait for your approval.
- **Codex.** Runs sandboxed and cannot touch the server machine.
- **Audit.** Every tool call, approval and denial is kept in the task
  history and in the audit log.
- **MCP with a user token.** Read-only by default.

## Desktop updates

- **Signature.** The `latest.json` manifest includes, for each platform, the
  SHA-256 of the artifact and an **Ed25519** signature over
  `termoak-update:v1:{platform}:{version}:{sha256}`.
- **Public key.** Compiled into the app (`TERMOAK_UPDATE_PUBKEY`). An update
  without a valid signature, with another hash or that is not newer is
  discarded.
- **Applying.** The download is kept aside and applied on the next start:
  the binary, the AppImage or the `.app` is replaced and the app relaunches.
- **Downloads through the server.** With `[updates]`, the server only serves
  the files of the latest release of each component (desktop, server and
  CLI), by their exact name; nothing else from the repository. The GitHub
  token is read-only and never leaves the server.
- **Generate your own keys** with `termoak-release keygen`. The secret key
  goes to the GitHub secrets (`TERMOAK_UPDATE_SECRET`) and the public key to
  the repository variables (`TERMOAK_UPDATE_PUBKEY`).

## Deployment recommendations

- Serve the server over TLS, directly with `tls_cert`/`tls_key` or behind
  Caddy or nginx.
- Behind a reverse proxy, enable `trust_forwarded_for` so the per-IP rate
  limit works. If the server is exposed to the internet, you can add
  fail2ban on the `429` responses.
- Enable two-step verification on administrator accounts.
- Back up `data_dir`, which holds `termoak.db` and `master.key`.

See [DEPLOYMENT.md](https://github.com/TermoakSSH/server/blob/main/docs/DEPLOYMENT.md).
