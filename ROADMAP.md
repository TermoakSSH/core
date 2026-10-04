# Roadmap

What exists, what is missing and in which order. Each component is released
separately (each repository's `scripts/release-local.sh status` shows what has unreleased
changes).

## Status

| Component | Version | Notes |
|---|---|---|
| Server | 0.1.x | API, web app, persistent sessions, AI, updates and downloads |
| CLI | 0.1.x | The full engine without a UI |
| Desktop | 0.1.x | Linux and Windows built in Docker; macOS is built on a Mac |
| Android | 0.3.x | Released as an APK |
| iOS | 0.3.x | Same interface; unsigned .ipa built on a Mac (Sideloadly or AltStore) |

## Done

- Own SSH engine: terminal, SFTP, port forwarding, ProxyJump, agent,
  certificates, TOFU, recording; **SOCKS5/SOCKS4/HTTP proxy** per host.
- Sessions that live on the server, shared with users, teams or by link;
  relay of local terminals. With the **session holder**, updating or
  restarting the server does not cut them and the apps reconnect on their
  own.
- Background multi-provider AI with approvals.
- Encrypted, synced vault; accounts with 2FA, teams, invitations, plans and
  a web app.
- Push notifications (APNs and FCM) and outgoing email (verification,
  password reset and invitations).
- Internationalization: English source with a Spanish translation; emails
  and notifications in each user's language; stable API error codes.
- Desktop: local and **serial** terminals, SFTP, AI with a copilot next to
  the terminal, sharing, signed self-update; links open when clicked.
- Mobile: hosts, groups, terminal with tabs, server sessions, AI with
  approvals, keychain and identities, snippets, known hosts, proxy and host
  chains.
- Releases without GitHub Actions (`scripts/release-local.sh`), per
  component, with downloads served by the server itself.

## Next (by priority)

1. **Open-source release**: split into the repositories of the
   [Termoak](https://github.com/TermoakSSH) organization (core, server,
   desktop, mobile-android, mobile-ios) under the AGPL-3.0, with the code
   and documentation in English.
2. **Testing on real devices**: Android, iOS 0.3 on a Mac, and the Windows
   fixes (tab close button, DPI, server sessions).
3. **Backups**: the Android keystore off the build machine, and a daily
   backup of the server database.
4. **API compatibility**: catch-all variant (`#[serde(other)]`) in the enums
   that clients receive, before more apps are installed.
5. **Mobile terminal**: selecting text (not just copying the screen) and, on
   iOS, opening links when tapped (Android already does).
6. **SFTP on mobile** (the engine already has it).
7. **Port forwarding and teams on mobile.**

## Later

- iOS on TestFlight / App Store (needs an Apple Developer account).
- Code signing on macOS (notarization) and Windows (SmartScreen).
- Serial port: configurable parity, stop bits and flow control.
- Proxy password on groups too (today only on the host).
- Pro plan: priority support and Termoak AI credit.
- A separate GitHub token to publish releases (the server's one stays
  read-only).

## Performance

- Remote terminals without Nagle on the server and the clients, and pending
  output grouped into a single message: full-screen programs (htop, vim)
  used to be painted in pieces with waits of up to 40 ms between them in
  server sessions.
- To be measured on devices: terminal painting on Android with very busy
  screens.
