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
- **Resolution.** `resolve_host` merges, in order, the settings of the host,
  of its group and parent groups, the identity and the keys, and also
  resolves the jump chain. The result is a `ResolvedHost` whose `Debug`
  hides the secrets.
- **Users and devices.** Passwords use Argon2id. Each device has an access
  token and a refresh token, and the database only stores their SHA-256
  hash. Refreshing rotates both tokens.

### `termoak-ssh`

- `Connection::connect` opens the ProxyJump chain (each hop is a
  `direct-tcpip` channel of the previous one) and authenticates in this
  order: key or certificate, agent, password, keyboard-interactive and,
  finally, asking for the password.
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
  (reuses connections for exec and SFTP).

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
  asks for the keyboard (`auto_grant` grants it at once). Revoking, changing
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
- `Workspace` puts together the vault, the store, the server and the known
  hosts verifier. The CLI, the desktop app and the FFI use it.

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

## Clients

- **Desktop** ([TermoakSSH/desktop](https://github.com/TermoakSSH/desktop)): GPUI with `gpui-component` and the
  `alacritty_terminal` emulator. A sidebar with hosts, keychain, snippets,
  port forwards, known hosts, server sessions and AI, plus terminal and SFTP
  tabs. It uses `termoak-client` directly. See
  [its README](https://github.com/TermoakSSH/desktop#readme).
- **Mobile**: SwiftUI and Jetpack Compose on top of `termoak-ffi` (UniFFI).
  See [MOBILE.md](MOBILE.md).
- **CLI** (`termoak`): every feature, with `--json` output for scripts.
