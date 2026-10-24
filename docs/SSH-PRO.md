# SSH pro (Termoak 0.7): security keys and snippets with variables

Status: **phase 3a done** (2026-10-24): design, core (v0.7.0-next.4),
server (0.7.0-next.4) and QA. Next: phase 3b (desktop + web) and phase 3c
(Android + iOS), with the checklists of §9.

Plan: `PLAN-0.7.md` §2 ("SSH pro") and §5 (phase 3). A copy of this
document lives in the core repository (`docs/SSH-PRO.md`); keep both equal.

---

## 1. Scope

1. **FIDO2 security keys** (YubiKey, SoloKey, Nitrokey, Titan...): the
   OpenSSH key types `sk-ssh-ed25519@openssh.com` and
   `sk-ecdsa-sha2-nistp256@openssh.com` (OpenSSH 8.2+ servers). Import from
   `id_ed25519_sk` / `id_ecdsa_sk` files, generate on the device, load
   resident (discoverable) keys from the device, authenticate from the apps
   and, through **signature forwarding**, from server sessions.
2. **Snippets with variables**: one template engine in the core for every
   app, the server's multi-host runs and startup snippets: built-ins
   (`{{host}}`, `{{user}}`, `{{date}}`...), prompts with defaults, selects,
   secrets, escaping.

Not in this phase: SSH certificates signed by a team CA (phase 4; sk keys
with an OpenSSH certificate already work, §3.5), agent forwarding of sk keys,
WebAuthn in the browser (the web cannot use security keys for SSH, §8.2).

---

## 2. Security keys: background

An OpenSSH "sk" key is a FIDO2 credential:

- **Public key**: the authenticator's EC P-256 or Ed25519 key, plus the
  **application** (the FIDO relying party id, `ssh:` by default; OpenSSH
  requires it to start with `ssh:`).
- **Key handle** (the FIDO **credential id**): stored in the "private key"
  file, which holds no secret key. For non-resident keys the key handle is
  usually the private key wrapped by the device's master secret, so it is
  only useful together with the device. It is still key material: whoever
  has it plus the device (and the PIN, when required) can sign. Termoak
  treats it like any private key: encrypted secret, never logged, hidden from
  Use-only members.
- **Flags** of the key: `0x01` user presence required (touch; cleared by
  `ssh-keygen -O no-touch-required`, which also needs the server's
  `no-touch-required` authorized_keys option), `0x04` user verification
  required (PIN or biometrics: `-O verify-required`; server option
  `verify-required`), `0x20` resident (discoverable; `-O resident`).
- **Signature**: the authenticator signs
  `authenticatorData || clientDataHash`, where `authenticatorData` is
  `SHA-256(application) || flags || counter` (no extensions) and
  `clientDataHash = SHA-256(message)`, the message being the SSH
  `publickey` userauth data (session id + request). So the signed bytes are
  exactly OpenSSH's `SHA-256(application) || flags || counter ||
  SHA-256(message)`. Ed25519 signs those bytes; ECDSA signs their SHA-256.
- **SSH signature blob**: `string alg || string sig || byte flags || uint32
  counter`, with `sig` raw (64 bytes) for Ed25519 and `mpint r || mpint s`
  for ECDSA.

### 2.1 How it fits russh 0.63

russh already speaks sk signatures for agents: `Handle::
authenticate_publickey_with(user, public_key, hash_alg, signer)` sends the
public key and, on `PK_OK`, hands the to-be-signed buffer (string session
id + userauth request) to an `auth::Signer`, which must return that buffer
with the encoded signature appended (`string(sig blob)`). The core
implements `Signer` (`termoak_ssh::sk::SkAuthSigner`) on top of a
`SecurityKeySigner`, builds the blob itself and **verifies the signature
against the public key before sending it** (a wrong device or key fails
locally with `security_key_wrong_key` instead of an opaque "rejected").
Certificates use `authenticate_certificate_with`. **No patch or fork of
russh is needed.**

---

## 3. Security keys: data model

### 3.1 The key entity

A security key is an ordinary SSH key (`EntityKind::Key`, `SshKey`), so
identities, hosts and groups reference it as before and it syncs, moves and
copies like any key:

| Field | Value |
|---|---|
| `algorithm` | `sk-ssh-ed25519@openssh.com` or `sk-ecdsa-sha2-nistp256@openssh.com` |
| `public_key` | OpenSSH public key (`sk-ssh-ed25519@openssh.com AAAA… comment`), what goes into `authorized_keys` |
| `fingerprint` | `SHA256:…` |
| `security_key` (new, optional) | `{application, user, touch_required, verify_required, resident, device}` |
| secret `private_key` | The OpenSSH sk "private key" file (`-----BEGIN OPENSSH PRIVATE KEY-----`): public key, application, flags, **key handle**, reserved. Optionally encrypted with a passphrase like any OpenSSH key |

`security_key`:

```json
{"application": "ssh:", "user": "openssh", "touch_required": true,
 "verify_required": false, "resident": false, "device": "YubiKey 5C NFC"}
```

- `device` is only a label ("which key it lives on"), shown in the apps.
- The private key file is the **source of truth**: the core reads the
  application, flags and key handle from it when it signs. `security_key`
  is derived from the file on import/generation (the core fills it) and is
  descriptive; an sk key without it (imported by an older app, which already
  accepted `id_ed25519_sk` files as regular keys) still works and the apps
  recognize it by its algorithm (`SshKey.is_security_key()` in the core).
- Newer cores **always write** `security_key` (`null` for regular keys).
  Older cores do not know it and drop it when they edit a key: the store
  keeps the stored value when the field is missing, like
  `settings.network_id` (core `store::entities::OMITTABLE`).
- Validation: `security_key` only on `sk-*` algorithms; `application`
  starts with `ssh:` and has at most 128 characters; `device` and `user` at
  most 64 characters.

### 3.2 Import and export

- `termoak_ssh::keys::import_private` already reads sk files (ssh-key
  parses them); it now returns `KeyMaterial.security_key` with the derived
  info. Encrypted sk files keep their passphrase rules.
- The public key in authorized_keys format is `public_key` (plus the
  options the user may want: `no-touch-required`, `verify-required`;
  `termoak_ssh::sk::authorized_keys_line(public_key, info)` writes them from
  the flags).

### 3.3 Generating a key on the device (make credential)

1. The core prepares the request: `sk::make_credential_request(options)`
   → `SkMakeCredentialRequest {algorithm, application, user_id, user_name,
   client_data_hash (random challenge), resident, require_verification,
   require_presence}`. `user_id` is OpenSSH's: the user name (default
   `openssh`) zero-padded to 32 bytes, so a resident key with the same
   application and user overwrites the one on the device, as with
   `ssh-keygen -K`.
2. The app's callback runs CTAP2 `authenticatorMakeCredential` with
   `rp.id = application`, `pubKeyCredParams = [ES256 (-7)]` or `[EdDSA
   (-8)]`, options `rk` (resident) and `uv` (verify required; with the PIN
   protocol as the platform library does it) and returns
   `SkCredential {authenticator_data, attestation_object?, device?}`.
3. The core parses `authenticatorData` (rpIdHash must be
   `SHA-256(application)`, the `AT` flag set, the credential id and the
   COSE public key: EC2/P-256/ES256 or OKP/Ed25519/EdDSA), builds the
   OpenSSH public key and the sk private file and saves the key
   (`TermoakCore::create_security_key`). Attestation is not verified (as
   OpenSSH by default); it is not stored.

### 3.4 Resident (discoverable) keys: loading them from the device

Like `ssh-keygen -K`: the app's callback enumerates the credentials whose
relying party starts with `ssh:` (CTAP 2.1 `authenticatorCredentialManagement`
`enumerateRPs` / `enumerateCredentials`, which needs the PIN) and returns
`[SkResidentCredential {application, credential_id, public_key_cose,
user_id, user_name}]`. The core turns each one into an sk key with flags
`touch_required | resident` (the device does not say whether UV was
required: the user can mark it) and saves the ones whose fingerprint is not
in the target vault yet (`TermoakCore::import_resident_security_keys`).
`getAssertion` with an empty allow list cannot do this (assertions carry no
public key).

### 3.5 Signing

`termoak_ssh::sk`:

```rust
#[async_trait]
pub trait SecurityKeySigner: Send + Sync {
    async fn sign(&self, request: SkSignRequest) -> Result<SkAssertion, SkError>;
}
pub struct SkSignRequest {
    pub algorithm: SkAlgorithm,          // Ed25519 | EcdsaP256
    pub application: String,             // rp id
    pub key_handle: Vec<u8>,             // credential id (allow list)
    pub public_key: String,              // OpenSSH, to find/confirm the key
    pub fingerprint: String,
    pub message: Vec<u8>,                // data to sign (clientData)
    pub client_data_hash: [u8; 32],      // SHA-256(message)
    pub require_presence: bool,          // CTAP2 option up
    pub require_verification: bool,      // CTAP2 option uv
    pub context: SkContext,              // host, username, key label, purpose, session id
}
pub struct SkAssertion { pub flags: u8, pub counter: u32, pub signature: Vec<u8> }
```

- `signature`: Ed25519 → 64 raw bytes; ECDSA → DER (what CTAP2 returns) or
  64 bytes `r || s`. `flags`/`counter` come from the assertion's
  authenticator data (bytes 32 and 33..37); a callback may also return the
  whole `authenticator_data` instead (FFI).
- `message` and `client_data_hash` are both given because libraries differ:
  CTAP2 itself and YubiKit take the 32-byte hash, ctap-hid-fido2 takes a
  "challenge" it hashes, Windows' webauthn.dll takes client data it hashes.
- The core checks the flags: `UP` must be set when the key requires touch
  and `UV` when it requires verification (else `security_key_failed`), and
  verifies the signature (else `security_key_wrong_key`).
- `ConnectOptions::with_security_key(signer)` (and `with_purpose`):
  without a signer, a host whose key is an sk key fails with
  `security_key_required`. When the device fails, the connection stops with
  the security key's error (a precise code) unless the host also has a
  saved password, which is then tried (never an interactive password
  prompt after a security key failure). A cancellation always stops. A key
  the server does not accept is an ordinary `ssh_auth_failed`.
- russh waits for the signed request once the server said "this key is
  acceptable": on a device error the core sends a request with an empty
  signature (the server answers "failure"), so the session stays usable.
- With a certificate (`SshKey.certificate`, `sk-…-cert-v01@openssh.com`)
  the certificate is offered and the security key signs.

### 3.6 Errors

`SkErrorCode`, the API/FFI code and the HTTP status where the server
returns it:

| Code | Status | Meaning |
|---|---|---|
| `security_key_required` | 409 | The key is a security key and nothing here can ask for it (no callback on this device; the session holder of an older server; a server connection without forwarding) |
| `security_key_no_device` | 409 | Server forwarding: none of your devices that can sign is online (an app open and signed in, with security keys enabled) |
| `security_key_timeout` | 504 | Nobody touched the key in time (forwarding: 60 s by default) |
| `security_key_cancelled` | 409 | The user cancelled |
| `security_key_not_found` | 409 | The device does not have this credential (another key plugged in, or the resident key was deleted) |
| `security_key_pin_required` | 409 | The key needs its PIN (user verification) and none was given |
| `security_key_pin_invalid` | 409 | Wrong PIN (or the PIN is blocked) |
| `security_key_wrong_key` | 409 | The signature does not match the public key (wrong device answered) |
| `security_key_unsupported` | 422 | The device or platform cannot do this (algorithm, resident keys, no NFC...) |
| `security_key_invalid` | 400 | Malformed credential, attestation or key file |
| `security_key_failed` | 502 | Other error from the device or its library (message from the platform) |

`SshError::SecurityKey {code, message}` in the engine; FFI
`TermoakError::SecurityKey` with `apiError.code` = the code (status 0 on the
device, the HTTP status from the server); the server's `ApiError` with the
same code. Session failures carry it in `status.reason` (text) and in the
session's `error`.

---

## 4. Security keys: FFI (mobile; the desktop uses the same Rust types)

```text
// Implemented by the app (blocking calls from a background thread, like AuthHandler).
callback interface SecurityKeyHandler {
  sign(request: SecurityKeySignRequest) -> SecurityKeyAssertion                 throws SecurityKeyError
  make_credential(request: SecurityKeyCredentialRequest) -> SecurityKeyCredential throws SecurityKeyError
  list_resident(request: SecurityKeyResidentRequest) -> [SecurityKeyResident]     throws SecurityKeyError
}
error SecurityKeyError { NoDevice, Timeout, Cancelled, NotFound, PinRequired, PinInvalid,
                         Unsupported, Failed }        // each with `message`; foreign exceptions → Failed

TermoakCore.set_security_key_handler(handler?)       // nil disables (and stops answering the server)
TermoakCore.has_security_key_handler() -> bool
TermoakCore.create_security_key(label, options: SecurityKeyOptions, comment, sync_mode?,
                                account_id?, vault_id?, handler) -> SshKey
TermoakCore.import_resident_security_keys(application_prefix?, verify_required, device?,
                                sync_mode?, account_id?, vault_id?, handler) -> [SshKey]   // only new fingerprints
security_key_request(options) -> SecurityKeyCredentialRequest            // pure: build the request
security_key_from_credential(request, credential, comment) -> SecurityKeyMaterial {details, private_key}
security_key_authorized_keys_line(public_key, info?) -> String
SshKey.security_key: SecurityKeyInfo?    (read-only; also derived for sk keys without details)
KeyDetails.security_key: SecurityKeyInfo?  (inspect_private_key of an id_*_sk file)
TermoakError.SecurityKey(message)        (apiError.code = security_key_*)
```

- `SecurityKeySignRequest` carries `application`, `key_handle`,
  `client_data_hash`, `message`, `algorithm`, `require_presence`,
  `require_verification`, `public_key`, `fingerprint`, and what to show:
  `host`, `username`, `key_label`, `device` (label), `purpose` (`connect`
  on this device; forwarded: `server_session`, `test`, `server` for
  `/exec`, SFTP and AI), `session_id`.
- `SecurityKeyAssertion {flags, counter, signature, authenticator_data?}`.
- Local connections (`connect_terminal`, SFTP, tunnels, exec) use the
  handler set on the core. Without a handler an sk key fails with
  `SecurityKey` / `security_key_required`.
- **Server forwarding on the device**: while a handler is set,
  `subscribe_events` opens the events socket with `?features=security_keys`
  and answers `security_key_request` messages by calling `sign` on a worker
  thread and sending `security_key_response` (§5). The listener still gets
  the request and `security_key_done` events (to show "Touch your key for
  the session on web1" and dismiss it). The desktop gets the same through
  `termoak_client::Accounts::set_security_key_signer`.

Snippet FFI: §7.4.

---

## 5. Security keys: forwarding for server-side connections

There is no physical key on the server. When a connection made **by the
server** (server session, also in the session holder; `POST
/hosts/{id}/test`; `/exec`; SFTP; AI tools) needs an sk key, the server asks
the **owner's** connected devices to sign, over the events WebSocket.

### 5.1 Protocol (events WebSocket, `GET /api/v1/events/ws`)

A device that can sign connects with `?features=security_keys` (comma list;
unknown features are ignored). Older clients do not send it and never get
these messages. `hello` echoes `features: ["security_keys"]`.

Server → device:

```json
{"type":"security_key_request","request_id":"…","expires_at":1791198108458,
 "purpose":"server_session","session_id":"…","host":"web1","address":"10.0.0.5",
 "username":"deploy",
 "key":{"id":"…","label":"YubiKey","fingerprint":"SHA256:…",
        "algorithm":"sk-ssh-ed25519@openssh.com","application":"ssh:",
        "key_handle":"<base64>","device":"YubiKey 5C"},
 "message":"<base64>","client_data_hash":"<base64>",
 "require_presence":true,"require_verification":false}
```

Device → server (same socket):

```json
{"type":"security_key_response","request_id":"…","flags":1,"counter":42,
 "signature":"<base64>"}
{"type":"security_key_response","request_id":"…","error":{"code":"cancelled","message":"…"}}
```

Server → the devices that got the request, once it is decided:

```json
{"type":"security_key_done","request_id":"…","result":"signed"|"failed"|"timeout"|"cancelled"}
```

Error codes from the device: `cancelled`, `timeout`, `not_found`,
`pin_required`, `pin_invalid`, `no_device` (no key connected to this
device), `unsupported`, `failed`.

### 5.2 Rules

- **Only the owner's devices**: the request goes to the events sockets of
  the session owner (the user whose vault access resolved the host) that
  declared `security_keys`. Responses are accepted only from those sockets,
  for a pending request of that same user; anything else is ignored.
- **Bound to the connection**: `message` contains the SSH session's
  exchange hash, so a signature is only valid for that SSH connection; the
  server keeps `(request_id → owner, session_id, public key, message)` and
  verifies the signature against the key and message before using it. The
  Termoak `session_id` is in the request so the app can show which session
  asks.
- **First good answer wins.** An error from one device does not end the
  request while other devices may still answer, except `cancelled`; when
  every device answered with an error the most specific one is used
  (`cancelled` > `pin_invalid` > `pin_required` > `not_found` > others).
- **Timeouts**: 60 s by default (`[sessions] security_key_timeout_secs`,
  10–300). No device online → `security_key_no_device` at once.
- **Audit**: `security_key.sign` in the host's vault with `{purpose,
  session, host, key (fingerprint), device (the answering device id), result,
  code?}`.
- **Session state**: while waiting, a server session shows
  `connecting` with "Touch your security key (YubiKey) on one of your
  devices…".
- **Holder**: the holder asks the server (`Question::SecurityKey`, new holder
  feature `security_keys`); a server whose holder does not announce it keeps
  sk sessions in its own process (like private networks with older holders).
  The holder protocol version does not change.
- **AI, SFTP and `/exec`**: connections of the server's pool forward too
  (purpose `server`, with the host and key): the user sees "the server wants
  to connect to web1" and touches the key, or the call fails with
  `security_key_timeout` / `security_key_no_device`.
- **E2EE vaults (phase 5)**: forwarding does not need the server to read the
  key handle; when vaults become E2EE the device will fill `key_handle`
  itself (the request then carries only the key id and fingerprint).

### 5.3 Limits

- The app must be open and signed in (events socket). Push wake-up for
  sign requests comes with the push work (UnifiedPush/APNs) of phase 4.
- The web cannot answer (§8.2): a web user with an sk key needs a phone or
  desktop app open.
- One request per SSH authentication; reconnects ask again.

---

## 6. Security considerations

- The key handle is stored as the key's secret (encrypted, `secret_hidden`
  for Use-only, `secret.reveal`/`secret.use` audited) and never logged. A
  stolen key handle is useless without the device (and its PIN when
  `verify_required`), but it reveals that the device has a credential.
- Signatures are verified by the core before use: a malicious or confused
  device cannot make the client send garbage, and the server only uses a
  forwarded signature that verifies over the exact message it asked for.
- The sign request shown to the user includes host, user, key and purpose:
  apps must show them and require an explicit action (the touch itself is
  the confirmation; apps should not auto-sign for background purposes without
  showing the request).
- Forwarding gives the server one signature per request, bound to one SSH
  connection; it cannot reuse it. A compromised server could ask for
  signatures for connections the user did not intend; the request shows the
  host and purpose, and every request is audited.
- `no-touch-required` keys sign without a touch: the apps say so in the key
  details (and the forwarding still needs the app open).
- Resident keys hold the user name on the device; loading them needs the PIN
  (credential management), which the platform library asks for; the core
  never sees the PIN.
- Test-only software authenticator (`termoak_ssh::sk::soft`, cargo feature
  `soft-sk`): its credential id *contains* the private key. It is never
  compiled into apps or the server binary (only tests and the QA tool).

---

## 7. Snippets with variables

### 7.1 Syntax

A **tag** is `{{` … `}}`; the text inside is trimmed. Tags:

| Tag | Variable |
|---|---|
| `{{name}}` | A built-in (below) or, for any other name, a prompt labelled `name` without default (the pre-0.7 behaviour). Names: letters, digits, `_` and `-` |
| `{{prompt:Label}}` | Free text asked to the user |
| `{{prompt:Label\|default}}` | Same, prefilled with `default` (everything after the first `\|`, trimmed) |
| `{{select:Label\|a\|b\|c}}` | One of the options (trimmed; empty and repeated ones dropped); the first is the default |
| `{{secret:Label}}` | Masked input; never remembered, stored, logged, audited or sent anywhere but into the command |

Built-ins (filled per host, never asked when there is a host):

| Built-in | Value |
|---|---|
| `host` | The address you connect to (`Host.address`) |
| `label` | The host's label |
| `user` | The SSH user (after identities and groups) |
| `port` | The SSH port |
| `group` | The host's group name (empty without one) |
| `date` | Local date `YYYY-MM-DD` (on the device; UTC on the server) |
| `time` | `HH:MM:SS` |
| `datetime` | `YYYY-MM-DDTHH:MM:SS` |
| `timestamp` | Unix seconds |

Rules:

- **Same label = same variable**: `{{prompt:Branch}}` twice is asked once;
  a plain `{{env}}` and `{{prompt:env|dev}}` are the same variable. The
  first tag defines it (kind, default, options).
- **Built-ins without a host** (a snippet pasted into a local terminal, the
  old `render_snippet`): the date/time ones are filled; `host`, `label`,
  `user`, `port`, `group` become prompts, as before 0.7.
- **A value given for a built-in wins** (older clients asked the user for
  `{{host}}` and send it; the server's `/exec` honours it).
- **Escaping**: `\{{` is a literal `{{` (the backslash is dropped) when
  what follows is a tag; before anything else the backslash stays as
  written, so old snippets with `\{{` in them do not change. (A literal
  backslash right before a tag's value cannot be written.)
- Spaces and line breaks around a tag's inside are trimmed (as before
  0.7: `{{ name }}`); a line break inside a typed tag makes it literal.
- **Compatibility rule**: anything between `{{` and `}}` that is not a valid
  tag (`{{ .Values.x }}`, `{{#each}}`, `{{foo:bar}}`, `{{a b}}`), and a `{{`
  without `}}`, stays literal, as before. A snippet without tags runs
  exactly as before (byte for byte).
- **Malformed typed tags** (`{{prompt:}}`, `{{select:Env}}` without options,
  `{{secret:Pass|x}}` with a default, a label over 64 characters, the same
  label with two kinds, more than 50 variables) are reported as **issues**.
  They render literally (never an error at run time), the editors show the
  issues, and saving through the API or the apps' editors rejects them
  (`invalid_snippet`, 400, `issues: [{start, end, message}]`). Pushed sync
  records are not checked (an older app may have written them).
- **Values** are inserted as they are (no shell quoting), as before. A
  select value must be one of its options. A prompt without default and a
  secret must have a value (`missing variable "Label"`).
- **Old cores** see only `{{name}}` tags: the new tags run literally there.

### 7.2 Engine (`termoak_core::template`)

- `parse(script) -> Template {segments, variables, issues}`;
  `Variable {key, kind: Builtin | Prompt | Select | Secret, label,
  default, options, positions}`.
- `Template::render(&values, &context) -> Result<String>`; `context` is
  `TemplateContext {host, label, user, port, group, now}` (all optional).
- `Template::prompts(&context)`: the variables to ask (built-ins without
  context included).
- `render_startup(script, context)`: built-ins, defaults and first options;
  anything else literal (startup snippets cannot ask).
- `Snippet::variables()` / `render()` keep their meaning (all variables,
  built-ins included, without context).
- Shared test vectors: `crates/termoak-core/tests/template_vectors.json`
  (the web's own implementation must pass them, §9).

### 7.3 Where it runs

| Where | How |
|---|---|
| Apps (single host, terminal) | `prompts(ctx)` → dialog → `render(values, ctx)` → send to the terminal |
| Apps (broadcast / multi-run) | One dialog for the shared prompts, then `render_for_hosts(values, contexts)`: each host gets its own built-ins |
| Server `POST /exec` with `snippet_id` | Parsed once; missing prompts → 400 before anything runs; rendered per host with that host's address/user/port/label/group |
| Startup snippets (`settings.startup_snippet_id`) | `resolve` renders built-ins and defaults (core: server sessions, holder and apps alike) |
| AI runbooks | The runbook builder escapes `{{` in recorded commands and keeps `{{host}}` (now a built-in) |
| REST `POST/PUT /snippets` | Rejects templates with issues (`invalid_snippet`) |

### 7.4 Remembered values and FFI

- Values are remembered **on the device** per snippet and host (or per
  snippet for runs without a host), never secrets, never synced:
  `TermoakCore.remember_snippet_values(snippet_id, host_id?, values)` /
  `snippet_values(snippet_id, host_id?)` (local `meta` table, key
  `snippet_values:<snippet>:<host|*>`). Secret variables are dropped before
  saving.
- FFI: `parse_snippet(script) -> SnippetTemplate {variables:
  [SnippetVariable {key, kind, label, default_value, options, builtin}],
  issues: [SnippetIssue {start, end, message}]}`,
  `snippet_prompts(script, context?)`, `render_snippet_with(script, values,
  context?)`, `render_snippet_for_hosts(script, values, contexts)`,
  `TermoakCore.snippet_context(host_id, account_id?) -> SnippetContext`.
  The old `snippet_variables` / `render_snippet` keep working.

---

## 8. Per-platform plan for the UI phases

### 8.1 Libraries (licences must be AGPL-3.0 compatible)

| Platform | Library | Licence | Transport | Notes |
|---|---|---|---|---|
| Desktop Linux/macOS | **ctap-hid-fido2** 3.6 (Rust, maintained, last release 2026-09) | MIT | USB HID | Any rp id; `MakeCredentialArgsBuilder` / `GetAssertionArgsBuilder` (takes a "challenge" = our `message`, hashed into the client data hash), PIN, CTAP 2.1 credential management (resident keys). Linux needs udev access to `/dev/hidraw*` (the usual `70-u2f.rules`; Flatpak: `--device=all`) |
| Desktop Windows | **webauthn.dll** (Windows WebAuthn API) via the `windows` crate | MIT/Apache-2.0 | USB, NFC, BLE (Windows handles it) | Since Windows 10 1903 only administrators can open FIDO HID devices, so ctap-hid-fido2 would need admin. webauthn.dll accepts any rp id from native apps (it is what Win32-OpenSSH/libfido2 use), shows the PIN/touch UI itself and supports resident keys (credential listing only on API v4+). Alternative: kanidm's `webauthn-authenticator-rs` (MPL-2.0, `win10` + `usb` + `nfc` features) |
| Android | **yubikit-android** `fido` + `android` modules | Apache-2.0 | USB (YubiKeys), NFC | `Ctap2Session.makeCredential` / `getAssertions` take the client data hash and any rp id; `ClientPin`, `CredentialManagement`. The platform FIDO2 API (Credential Manager / `Fido2ApiClient`) binds the rp id to the app's Digital Asset Links domain, so it cannot use `ssh:` |
| iOS | **YubiKit iOS** (`YKFFIDO2Session`) | Apache-2.0 | NFC (`YKFNFCConnection`), Lightning (YubiKey 5Ci accessory) | Any rp id with the client data hash. Apple's `ASAuthorizationSecurityKeyPublicKeyCredentialProvider` binds the rp id to associated domains (no `ssh:`). USB-C keys on iPhone 15+/iPad: YubiKit's smart-card connection does not carry FIDO2; check on a device in 3c and document what works |
| Web | none | — | — | Browsers bind WebAuthn rp ids to the site's domain: the web cannot sign `ssh:` credentials. The web shows sk keys, imports their files and public keys, and server sessions with sk keys are signed by the user's phone or desktop through forwarding |

libfido2 (BSD-2-Clause, Yubico; what OpenSSH uses) was considered for the
desktop: it is the most complete, but needs the C library on three platforms
and its Rust bindings (`libfido2-sys`, `fido-rs`) see little use; kept as a
fallback.

### 8.2 What can be tested without a physical key

- Everything in the core and the server, with the software authenticator
  (`soft-sk`): generating (make credential → authenticator data → key),
  signing (ECDSA P-256 and Ed25519), flags (`no-touch-required`,
  `verify-required`), wrong key, cancel/timeout/PIN errors, resident key
  import, authentication against a real OpenSSH sshd (`openssh.rs` tests,
  QA's sshd container), forwarding through the events socket (server tests
  and QA with a simulated device), the holder path.
- In the apps: the FFI handler with a fake implementation (unit tests),
  screens with fixtures, the forwarding flow with a simulated device (the
  QA tool `sktool device` answering for a desktop/phone account).
- Needs a real key: the platform libraries themselves (USB HID permissions,
  NFC sessions, PIN UI, Windows Hello dialogs), touch timing and resident key
  enumeration on real firmware.

---

## 9. Checklists for the UI phases

### 9.1 Phase 3b: desktop + web

Desktop (core v0.7.0-next.4):
- [ ] `SecurityKeySigner` implementation: ctap-hid-fido2 on Linux/macOS,
      webauthn.dll on Windows; device picker when several keys; touch prompt
      (toast/dialog with host, user, key, purpose; cancel); PIN dialog when
      `require_verification` or the device asks; map errors to `SkError`.
- [ ] `ConnectOptions::with_security_key` for terminals, SFTP, tunnels,
      exec, local AI (`Workspace::connect` takes it through the prompter path).
- [ ] `Accounts::set_security_key_signer` so the events socket answers
      server forwarding; a visible "Touch your key for the server session on
      web1" toast with cancel; `security_key_done` dismisses it.
- [ ] Keys: "New security key" (algorithm, application, resident, verify
      required, no-touch, device label) → `create_security_key`; "Load from
      security key" (resident) → `import_resident_security_keys`; import of
      `id_*_sk` files; key details with application, flags, device; the
      authorized_keys line with options; never "export private key" wording
      for sk files ("key handle file").
- [ ] Errors by code (`security_key_*`), en/es texts.
- [ ] Snippets: editor with live issues (`parse`), variable list with kinds;
      run dialog from `prompts(ctx)` (select → dropdown, secret → masked,
      defaults prefilled, remembered values per snippet+host); broadcast /
      multi-run uses `render_for_hosts` (one dialog, per-host built-ins);
      server `/exec` with `snippet_id` + `variables`.
- [ ] Tests with the software authenticator (feature `soft-sk` in dev
      dependencies) and Xvfb screenshots.

Web:
- [ ] Keys page: sk keys with a badge, application, flags, device; import of
      `id_*_sk` files and of public keys; no "generate security key" (needs an
      app); explain that sessions with them are confirmed on your phone or
      desktop.
- [ ] Server session state "Touch your security key on one of your devices…"
      and errors `security_key_no_device` / `_timeout` / `_cancelled` with
      texts.
- [ ] Snippet editor: issues from the API's `invalid_snippet` (and a JS port
      of the parser that passes `template_vectors.json`); run dialog with
      prompts/selects/secrets for `/exec`; remembered values in localStorage
      (never secrets).
- [ ] QA: web tests for both.

### 9.2 Phase 3c: Android + iOS

Android:
- [ ] yubikit-android (`fido`, `android`): USB and NFC discovery; a
      `SecurityKeyHandler` (Kotlin) running `getAssertions` with the
      request's client data hash and rp id, `makeCredential`, credential
      management for resident keys; PIN dialog (`ClientPin`); bottom sheet
      "Tap or plug in your security key" with host/user/key/purpose and cancel.
- [ ] `setSecurityKeyHandler` at start; `subscribeEvents` already answers
      forwarding (foreground only); show/dismiss the sheet from
      `security_key_request` / `security_key_done`.
- [ ] Keys: new security key, load resident keys, import `id_*_sk`, details,
      authorized_keys line; errors by `apiError.code`; en/es.
- [ ] Snippets: same as desktop (prompts, selects, secrets, remembered
      values, broadcast with `render_for_hosts`).
- [ ] Rebuild the `.so` (the ones in core's jniLibs are from before 0.7).
- [ ] JVM tests with a fake handler; LiveTest against staging with the
      software authenticator answering as "the phone" (JNA build).

iOS:
- [ ] YubiKit iOS: NFC (`YKFNFCConnection`, NFC entitlement and
      `NFCReaderUsageDescription`, ISO7816 AID `A0000006472F0001`), Lightning
      (accessory, `com.yubico.ylp` protocol in Info.plist); a
      `SecurityKeyHandler` (Swift) for sign / make credential / resident
      keys; PIN sheet; "Hold your key near the top of the iPhone" UI.
- [ ] Same keys, snippets and forwarding work as Android; demo mode answers
      the new calls.
- [ ] XCTest with a fake handler; compile on the Mac.

---

## 10. Compatibility summary

- Old cores (0.2–0.6) decode sync records of sk keys (`security_key` is an
  unknown field they ignore); they cannot sign with them (they fail with a
  key error at connect time, as they did before with imported `id_*_sk`
  files) and their edits keep `security_key` on the server. sk keys are not
  hidden from legacy sync or sync v2 clients: hosts referencing them must
  keep resolving.
- Snippets: plain `{{name}}` keeps its meaning everywhere; `{{host}}`,
  `{{user}}`, `{{port}}`, `{{label}}`, `{{group}}`, `{{date}}`, `{{time}}`,
  `{{datetime}}`, `{{timestamp}}` are now filled automatically when there is a
  host (a value sent for them still wins). New tags are literal on old cores.
- Events socket: new message types only for sockets with
  `features=security_keys`.
- Holder: new feature flag, same protocol version.
- No database schema change.
