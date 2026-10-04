# Termoak core

The shared Rust crates of [Termoak](https://termoak.com), an open-source SSH
client for desktop and mobile with an optional self-hosted server, and the
`termoak` command-line client.

| Crate | What it is |
|---|---|
| `termoak-core` | Models, SQLite, encrypted vault, users, sessions and host resolution |
| `termoak-ssh` | SSH engine: connection, terminal, exec, SFTP, forwarding, keys, recording |
| `termoak-ai` | AI engine: providers, agent, tools, policies, MCP |
| `termoak-client` | API client, sync, remote sessions and relay |
| `termoak-ffi` | UniFFI layer for the Swift and Kotlin apps |
| `termoak-update` | Signed self-update and the `termoak-release` tool |
| `termoak-cli` | The `termoak` CLI |

`bindings/` holds the Swift package and the Android (Kotlin) module generated
from `termoak-ffi`; `scripts/` builds the native libraries for Android and iOS.

## The Termoak repositories

| Repository | Contents |
|---|---|
| **[TermoakSSH/core](https://github.com/TermoakSSH/core)** | Shared crates (SSH engine, vault, API client, AI engine, FFI bindings, updates) and the `termoak` CLI |
| [TermoakSSH/server](https://github.com/TermoakSSH/server) | `termoak-server`: HTTP/WebSocket API, basic web app, deployment files |
| [TermoakSSH/desktop](https://github.com/TermoakSSH/desktop) | Desktop app (GPUI) for Windows, Linux and macOS |
| [TermoakSSH/mobile-android](https://github.com/TermoakSSH/mobile-android) | Android app (Jetpack Compose) |
| [TermoakSSH/mobile-ios](https://github.com/TermoakSSH/mobile-ios) | iOS app (SwiftUI) |
| [TermoakSSH/public-web](https://github.com/TermoakSSH/public-web) | Public website of termoak.com: landing, pricing and downloads |

## Using the libraries

The crates are not published on crates.io. Depend on them through a git tag
of this repository (one `vX.Y.Z` tag for every library):

```toml
[dependencies]
termoak-core = { git = "https://github.com/TermoakSSH/core", tag = "v0.2.0" }
termoak-ssh = { git = "https://github.com/TermoakSSH/core", tag = "v0.2.0" }
```

To work on core and an app at the same time, point the app to your checkout
without touching its `Cargo.toml`, e.g. in the app's `.cargo/config.toml`
(not committed):

```toml
[patch."https://github.com/TermoakSSH/core"]
termoak-core = { path = "../core/crates/termoak-core" }
termoak-ssh = { path = "../core/crates/termoak-ssh" }
# ...one line per crate the app uses
```

The mobile apps include this repository as a git submodule in `core/`, pinned
to a tag: they build the native library from it and use `bindings/`. See
[docs/MOBILE.md](docs/MOBILE.md).

## The CLI

Download it from the [releases](https://github.com/TermoakSSH/core/releases)
(`cli-vX.Y.Z`: Linux, Windows and macOS) or build it with Rust 1.89 or later:

```sh
cargo install --locked --git https://github.com/TermoakSSH/core termoak-cli
```

```sh
# Everything works without a server too
termoak keys generate my-key
termoak hosts add web1 10.0.0.5 --user deploy --key my-key --tag prod
termoak connect web1
termoak exec @prod -- uptime

# With a server: sync, persistent sessions and AI
termoak register https://termoak.example.com --email you@example.com
termoak sync
termoak connect web1 --server        # Ctrl+] detaches; the session stays alive
termoak sessions attach <id>
termoak sessions share <id> --link   # view-only link
termoak ai ask "why is web1 slow?" --hosts web1

# Accounts, teams and import
termoak hosts import --dry-run       # preview of ~/.ssh/config
termoak 2fa enable                   # shows the QR code in the terminal
termoak teams create Ops
termoak teams add Ops bob@example.com
termoak sessions share <id> --team Ops
termoak admin invite --email carol@example.com --team Ops
```

## Development

```sh
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace          # integration tests use the system sshd (Linux)
scripts/generate-bindings.sh    # after changing the termoak-ffi API (commit the result)
```

Releases are made with `scripts/release-local.sh` (no GitHub Actions needed):

```sh
scripts/release-local.sh status              # what has unreleased changes
scripts/release-local.sh version cli 0.2.1   # bump the CLI
scripts/release-local.sh build cli           # dist/cli/
scripts/release-local.sh publish cli         # the cli-vX.Y.Z GitHub release

scripts/release-local.sh version ffi 0.2.1   # bump every library ([workspace.package])
git commit -am "Libraries 0.2.1" && git push
git tag v0.2.1 && git push origin v0.2.1     # what the server, desktop and mobile apps use
scripts/release-local.sh build ffi           # optional: prebuilt Android/iOS libraries
scripts/release-local.sh publish ffi         # the ffi-vX.Y.Z GitHub release
```

The `vX.Y.Z` library tags are plain git tags, without a GitHub release.

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [AI engine](docs/AI.md)
- [Security](docs/SECURITY.md)
- [Mobile apps and the FFI layer](docs/MOBILE.md)
- [Internationalization](docs/I18N.md)
- [Roadmap](ROADMAP.md)
- Server: [HTTP API](https://github.com/TermoakSSH/server/blob/main/docs/API.md), [WebSocket protocol](https://github.com/TermoakSSH/server/blob/main/docs/WEBSOCKET-PROTOCOL.md), [Deployment](https://github.com/TermoakSSH/server/blob/main/docs/DEPLOYMENT.md)

## Contributing and translations

Bug reports, fixes, features and translations are welcome: see
[CONTRIBUTING.md](CONTRIBUTING.md). Translating Termoak into your language
needs no programming: copy the English strings file of an app, translate it
and open a pull request ([docs/I18N.md](docs/I18N.md)).

## License

Copyright © Ohz Digital SL.

Termoak is free software released under the
[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only).

"Termoak" and the Termoak logo are trademarks of Ohz Digital SL and are not
covered by the code license: see [TRADEMARK.md](TRADEMARK.md).
