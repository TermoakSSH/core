# Architecture

```
                    ┌──────────────────────── termoak-server ───────────────────────────┐
  Desktop (GPUI)  ──┤  HTTP (axum) · session WebSocket · events WebSocket · MCP · web app │
  CLI             ──┤                                                                   │
  iOS / Android   ──┤  SessionManager ── TerminalSession ── russh ──▶ hosts             │
   (UniFFI)         │  AiEngine ─────── providers (Claude, OpenAI, Codex, OpenCode...)  │
                    │  Store (SQLite + encrypted vault)                                 │
                    └───────────────────────────────────────────────────────────────────┘
```

Clients connect to their hosts over SSH directly, with their own engine. The
server is optional: it adds sync, persistent and shared sessions, and
background AI.

## Crates

The shared crates and the CLI live in [TermoakSSH/core](https://github.com/TermoakSSH/core); `termoak-server` lives in
[TermoakSSH/server](https://github.com/TermoakSSH/server) and depends on them through a git tag (`vX.Y.Z`), like the
[desktop app](https://github.com/TermoakSSH/desktop). The mobile apps include core as a git submodule.

### `termoak-core`

- **Model.** Every entity (hosts, groups, identities, keys, snippets, port
  forwards, known hosts and AI memories) implements the `Entity` trait. Each
  one has a public part and a secret part. The secret part is stored
  encrypted with XChaCha20-Poly1305. The AAD is `termoak:{kind}:{id}`, so a
  secret cannot be moved to another record.
- **Store.** A single generic entity table, in JSON, with the `rev`,
  `dirty`, `deleted` and `updated_at` columns. Clients use the same schema
  with `owner = Uuid::nil()`. All SQLite access goes through
  `spawn_blocking`.
- **Vaults** (`store/vaults.rs`, schema v9). Every entity is in a vault
  (`entities.vault_id`); every user has a personal vault whose id is the
  user id, users own `shared` vaults and teams own `team` vaults. On the
  server access is decided only by the vault: `VaultAccess` (the user's
  effective role in every vault, the maximum by rank of owner, team role,
  team member role and grants) is cached per user and invalidated by every
  change to vaults, grants, teams or team members. The vault-scoped
  functions (`list_in`, `get_in`, `save_in`, `delete_in`, `vault_changes`,
  `apply_remote_v2`, `move_entities`, `transfer`, `resolve_in`) take it;
  the owner-based ones (`list`, `get`, `save`, `apply_remote`...) stay for
  the clients' own stores. Every secret opened for a user goes through one
  check, `VaultAccess::authorize_secret` (`Reveal` needs Editor, `Server`
  any role, `Credentials` Editor or a non-Strict Use-only).
- **Vault keys.** On the server each vault has its own key (VK), created on
  the first secret written to it and wrapped with the master key
  (`vault_key_wraps`, recipient `server`; per-member wraps are reserved for
  end-to-end encrypted vaults). New secrets use the AAD
  `termoak:vault:{vault}:{version}:{kind}:{id}`; older ones
  (`key_version IS NULL`, master key and `aceitunoak:{kind}:{id}`) still
  open and are resealed in the background. Unwrapped keys are cached (LRU,
  wiped on drop). Moving an item reseals its secret; deleting a vault
  deletes its key. Clients keep sealing with their device key.
- **Transfers** (`transfer.rs`). A pure planner for moving or copying items
  between vaults (selection of groups, hosts, forwards, memories and known
  hosts; dependencies moved, copied or detached; groups flattened), shared
  by the server and the clients.
- **Resolution.** `resolve_host` merges, in order, the settings of the host,
  of its group and parent groups, the identity and the keys, and also
  resolves the jump chain. The result is a `ResolvedHost` whose `Debug`
  hides the secrets. `resolve_in` (server) looks every reference up in the
  host's vault only: a reference to another vault resolves as missing, so
  nobody can make the server use a key from a vault they cannot see.
  `resolve_local` (clients) does the same in an account store and falls back
  to the device store for "This device" items.
- **Users and devices.** Passwords use Argon2id. Each device has an access
  token and a refresh token, and the database only stores their SHA-256
  hash. Refreshing rotates both tokens.

### `termoak-ssh`

- `Connection::connect` opens the ProxyJump chain (each hop is a
  `direct-tcpip` channel of the previous one) and authenticates in this
  order: key or certificate, agent, password, keyboard-interactive and,
  finally, asking for the password. `Connection::latency` times a
  `keepalive@openssh.com` global request on the open connection (no new
  channel; a failure reply counts as an answer).
- `TerminalSession` splits reading from writing. All output goes through an
  `OutputHub`, which keeps a bounded scrollback and broadcasts it. When a
  viewer attaches, it gets a snapshot and the stream from that point, with
  no gaps or duplicates. That is what makes detaching and coming back
  lossless.
- `HostKeyVerifier` and `Prompter` are traits. The CLI asks on the terminal,
  the desktop app opens a dialog and the server forwards the question over
  WebSocket to the session owner.
- Other modules: `exec` (with a timeout), `sftp`, `forward` (L, R and a
  built-in SOCKS5 for D), `keys` (generation, import and fingerprints),
  `recording` (asciicast v2), `detect` (remote operating system) and `pool`
  (reuses connections for exec, SFTP and the AI on the server; it checks the
  user's vault access on every call and drops connections when it is
  revoked).
- `telnet::TelnetSession` is the terminal of hosts whose `protocol` is
  `telnet` (RFC 854): TCP or the host's proxy, option negotiation (ECHO,
  SUPPRESS-GO-AHEAD, TERMINAL-TYPE, NAWS on every resize, BINARY if the host
  asks; anything else is refused, RFC 1143 rules so it never loops), `IAC`
  escaping and the NVT end of line (CR NUL / CR LF), latency with a
  `TIMING-MARK`, and an optional automatic login that answers the first
  `login:` / `Password:` prompts of the first 30 seconds, each once. It has
  the same shape as `TerminalSession`, and `Terminal` holds either.
  `Connection::connect` refuses Telnet hosts (no SFTP, tunnels, jump hosts
  or server sessions over Telnet).
- `StoreVerifier` keeps known hosts in the store: owner-based on clients;
  on the server it looks in the host's vault and then the user's personal
  vault, and saves a new key where the user is Editor.

### `termoak-server`

- **REST API** under `/api/v1` (see [API.md](https://github.com/TermoakSSH/server/blob/main/docs/API.md)). The OpenAPI contract
  is served at `/api/openapi.json`.
- **`SessionManager`.** There are two kinds of session:
  - `server`: the SSH connection lives on the server.
  - `relay`: the terminal lives on a client, which relays it to share it.

  Each session tracks its viewers, with `owner`, `control` or `view` access.
  Input typed while the session is connecting is queued and sent once it
  opens.
- **Session holder** (`termoak-server sessions-holder`, optional). A
  separate process that keeps the SSH connections of `server` sessions: the
  server talks to it over a Unix socket (`holder/proto.rs`), keeps a copy of
  the scrollback and forwards input to it. Whatever only the server knows
  (known hosts, passwords that must be asked to the user), the holder asks
  for. When the server restarts, it recovers every session with its
  scrollback from the holder and the apps reconnect on their own, so
  updating the server cuts nothing. The holder serves a single server: if
  another one connects, the previous one stops using it.
- **Sharing.** Shares can target a user, a team or a link (with a waiting
  room: `require_approval`). The participants of a session (people, not
  sockets) and the keyboard live in the server's `room` module: one driver
  at a time, the owner can always type, everyone else joins read-only and
  asks for the keyboard (`auto_grant` grants it at once). The owner can
  hand it over for a while (1-240 minutes) and the server takes it back
  when the time is up. Revoking, changing
  (`PATCH`) or expiring a share, or leaving a team, re-checks the access of
  everyone affected: whoever has no other valid share is sent away with a
  stable code (`revoked`, `kicked`, `expired`...).
- **Events.** `/api/v1/events/ws` reports AI progress, approvals and
  sessions opened, closed or shared (see
  [WEBSOCKET-PROTOCOL.md](https://github.com/TermoakSSH/server/blob/main/docs/WEBSOCKET-PROTOCOL.md)). The mobile apps use it
  while open; push notifications (APNs and FCM) cover them when closed.
- **MCP** at `/api/v1/mcp`. The AI tools are available to external agents:
  Codex CLI with a per-task token, or any MCP client with a user token.
- **Web app** at `/`, embedded in the binary: sign in and sign up, sessions
  with a terminal in the browser, teams and account settings.
- **i18n.** Emails and push notifications are translated to each user's
  `locale` (`locales/<lang>.json`); API errors carry stable codes that
  clients translate. See [I18N.md](I18N.md).
- **Audit log** of sign-ins, sessions, shares, AI commands and revealed
  secrets.

### `termoak-ai`

See [AI.md](AI.md).

### `termoak-client`

- `ApiClient` renews the token automatically.
- `SyncEngine` syncs by `rev`, resolving conflicts with *last writer wins*
  on `updated_at`. Entities or secrets marked *this device only* are never
  sent.
- `RemoteTerminal` attaches to server sessions and `RelayShare` shares a
  local terminal. If the connection drops, both reconnect on their own for a
  few minutes (`RemoteTerminal` signals `Reconnecting` and, when back,
  `Resync` with the full scrollback; `RelayShare` sends the whole screen
  again). They speak protocol 2: `RemoteTerminal::can_write` says whether
  input and resizes reach the terminal (they are not sent otherwise), and
  `RemoteEvent::Ended` carries the code when the server sends you away (no
  reconnection then). `RelayShare::subscribe` reports participants, requests
  and the driver's size to the host, which acts as the owner.
  `RemoteTerminal::latency` times the protocol's `ping` / `pong` (the
  round trip to the Termoak server, not to the host behind it).
- `Workspace` puts together the vault key, the stores, the servers and the
  known hosts verifier. The CLI, the desktop app and the FFI use it.
- **Several accounts** (one per server and user): the device store
  (`termoak.db`: "This device" items, settings, command history and the
  `accounts` registry) plus one store per account (`accounts/<id>.db`, the
  same schema, a mirror of the vaults the account can access). Every store
  uses the device key; account tokens are sealed with AAD
  `termoak:account-tokens:<id>`. `Account` has its own API client, sync
  (v2 when `/info.features.sync_v2`, otherwise the legacy sync with one
  implicit personal vault) and events WebSocket (reconnects; `vault` events
  trigger a sync). `items` lists, saves, deletes, resolves and transfers
  across the stores: `Scope::Device` or `Scope::Account(id)`. Hosts resolve
  inside their vault, then in the device store; Use-only hosts get
  just-in-time credentials from the server (memory only, wiped once
  connected). Signing out of an account deletes its store.
- `servers::canonical` is the form of every server URL (and the moved
  `aceitunoak.ohz.ovh` → `termoak.com` rule); `OFFICIAL_SERVER` can be
  overridden at build time with `TERMOAK_OFFICIAL_SERVER`.
- `layout::migrate` moves 0.3 data (one store, one server in `meta`) to
  layout 2 once: a `VACUUM INTO` backup (`termoak.db.pre-accounts`, 30
  days), an `accounts` row for the old server (signed in or not), its synced
  rows copied to the account store and checked before they leave the device
  store; `device_only` rows stay. It resumes with the same account if
  interrupted.

### `termoak-cli`, `termoak-ffi` and `termoak-update`

- `termoak-cli` is the `termoak` command: every feature, with `--json`
  output for scripts.
- `termoak-ffi` exposes the engine to Swift and Kotlin through UniFFI. See
  [MOBILE.md](MOBILE.md).
- `termoak-update` implements the signed desktop updates and the
  `termoak-release` tool that creates the keys and signs the releases. See
  [SECURITY.md](SECURITY.md#desktop-updates).

### Sync

1. The client sends its dirty records and the last `rev` it knows.
2. The server applies each change if it is newer than its own and returns
   everything that changed since that `rev`.
3. Deletions travel as tombstones (`deleted`).
4. Secrets are encrypted with the master key of each side: in transit they
   travel in plain text inside TLS and are encrypted again when stored.

Sync v2 (`POST /api/v1/vaults/sync`) keeps one cursor per vault (the
highest global `rev` delivered for it), returns the authoritative list of
vaults the user can access (a missing one was lost: the client wipes it),
departures of moved items (`entity_departures`), explicit rejections, a
`resync` list when the role changes between Use-only and Editor, and pages
with `more`. Use-only vaults never send secrets (`has_secret` instead). The
legacy `/api/v1/sync` serves only the personal vault, with departures as
deletions, for apps before vaults.

## Clients

- **Desktop** ([TermoakSSH/desktop](https://github.com/TermoakSSH/desktop)): GPUI with `gpui-component` and the
  `alacritty_terminal` emulator. A sidebar with hosts, keychain, snippets,
  port forwards, known hosts, server sessions and AI, plus terminal and SFTP
  tabs. It uses `termoak-client` directly. See
  [its README](https://github.com/TermoakSSH/desktop#readme).
- **Mobile**: SwiftUI and Jetpack Compose on top of `termoak-ffi` (UniFFI).
  See [MOBILE.md](MOBILE.md).
- **CLI** (`termoak`): every feature, with `--json` output for scripts.
