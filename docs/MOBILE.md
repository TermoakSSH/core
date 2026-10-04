# Mobile apps (iOS and Android)

The iOS (SwiftUI) and Android (Jetpack Compose) apps embed the same Rust
engine as the desktop app and the CLI, through `crates/termoak-ffi` and
[UniFFI](https://mozilla.github.io/uniffi-rs/). The interface is native; the
vault, SSH, sync and the server client are Rust.

## Architecture

```
┌──────────────── App (SwiftUI / Compose) ─────────────────┐
│  Views, terminal emulator, dialogs, Keychain/Keystore    │
└──────────────┬───────────────────────────────┬───────────┘
               │ Swift / Kotlin (generated)    │
┌──────────────▼───────────────────────────────▼───────────┐
│ termoak-ffi (UniFFI)                                     │
│  TermoakCore ── local encrypted vault (SQLite)           │
│        │     ── local SSH engine: SshSession,            │
│        │        TerminalHandle, SFTP, tunnels, exec      │
│        └──── server client: login, sync, API,            │
│                 persistent sessions, AI, events          │
└──────────────┬───────────────────────────────┬───────────┘
          direct SSH                    HTTPS + WebSocket
               ▼                               ▼
         your servers                   Termoak server
```

- **Local engine.** Hosts, groups, identities, keys, snippets, tunnels and
  known hosts live in a database on the device, with the secrets encrypted.
  SSH connections go out from the phone itself: they work without a server
  and without a connection to it.
- **Server** (optional). It adds what a phone cannot do on its own:
  - **Persistent sessions**: the terminal runs on the server and survives iOS
    or Android suspending the app. The phone attaches and detaches whenever
    it wants and gets the scrollback back when it returns.
  - **Shared sessions**: invite other users or share a link
    (`termoak://join?server=...&token=...`), and share a local terminal
    (relay).
  - **Background AI**: tasks run on the server; the phone starts them,
    follows their progress and approves the actions that change something.
  - **Sync** of the vault across devices. Anything marked `DeviceOnly` never
    leaves the phone.
- **Notifications.** While the app is open, `subscribeEvents` (WebSocket
  `/api/v1/events/ws`) reports pending approvals, finished tasks and sessions
  shared with you in real time. While it is closed, the server sends push
  notifications (APNs and FCM) for the same events: see
  [Push notifications](#push-notifications).

## What is in this repository

The apps live in [TermoakSSH/mobile-android](https://github.com/TermoakSSH/mobile-android) and
[TermoakSSH/mobile-ios](https://github.com/TermoakSSH/mobile-ios); both include this repository as a git
submodule in `core/`, pinned to a release tag.

| Path | Content |
|---|---|
| `crates/termoak-ffi` | The FFI layer (UniFFI macros) and its tests |
| `crates/termoak-ffi/uniffi.toml` | Module and package names of the bindings |
| `bindings/swift` | Swift package: `Package.swift`, generated API (`Sources/TermoakFFI`) and helpers (`Sources/TermoakKit`) |
| `bindings/kotlin` | Android module: `build.gradle.kts` and generated API (`src/main/kotlin`) |
| `scripts/generate-bindings.sh` | Regenerates the Swift and Kotlin bindings |
| `scripts/build-ios.sh` | Builds for iOS and creates `termoak_ffiFFI.xcframework` |
| `scripts/build-android.sh` | Builds for Android with `cargo-ndk` and puts the `.so` files in `jniLibs` |

The generated bindings are committed so you can start without building Rust;
the binaries (xcframework and `.so`) are not. CI
(`.github/workflows/ci.yml`) checks that the bindings are up to date: if you
change the `termoak-ffi` API, run `scripts/generate-bindings.sh` and commit
the result.

## Building

> **Status:** `scripts/build-ios.sh`, `scripts/build-android.sh`,
> `Package.swift` and the bindings' `build.gradle.kts` are not exercised by
> CI (there is no Mac or NDK in CI). The apps are built in their own
> repositories: Android in Docker with `scripts/release-local.sh build android`
> and iOS with `scripts/build-ipa.sh` on a Mac.

### iOS

Requirements: macOS with Xcode and [rustup](https://rustup.rs).

```sh
scripts/build-ios.sh            # release (or: scripts/build-ios.sh debug)
```

The script builds for `aarch64-apple-ios` (device), `aarch64-apple-ios-sim`
and `x86_64-apple-ios` (simulators, merged with `lipo`), regenerates the
bindings and creates `bindings/swift/termoak_ffiFFI.xcframework` with the
static library and the C module.

In Xcode: *File › Add Package Dependencies… › Add Local…* and pick
`bindings/swift`. In your code:

```swift
import TermoakKit   // re-exports the generated API (TermoakFFI)
```

Minimum deployment target: iOS 15 (`IPHONEOS_DEPLOYMENT_TARGET`).

#### App and .ipa

The iOS app lives in [TermoakSSH/mobile-ios](https://github.com/TermoakSSH/mobile-ios), which includes this
repository as a git submodule (`core/`): see its README.

### Android

The Android app lives in [TermoakSSH/mobile-android](https://github.com/TermoakSSH/mobile-android), which
includes this repository as a git submodule (`core/`) and builds the
libraries itself: see its README.

To use the engine from another project, build the libraries.

Requirements: Android NDK (`ANDROID_NDK_HOME`), rustup and
`cargo install cargo-ndk`.

```sh
export ANDROID_NDK_HOME=$ANDROID_HOME/ndk/<version>
scripts/build-android.sh        # release; ABIS="arm64-v8a" to go faster
```

It produces
`bindings/kotlin/src/main/jniLibs/{arm64-v8a,armeabi-v7a,x86_64}/libtermoak_ffi.so`
(minimum API 24, configurable with `ANDROID_API`) and regenerates the
bindings.

`bindings/kotlin` is an Android library module. In your project:

```kotlin
// settings.gradle.kts
include(":termoak")
project(":termoak").projectDir = file("../core/bindings/kotlin")   // a checkout of github.com/TermoakSSH/core

// app/build.gradle.kts
dependencies { implementation(project(":termoak")) }
```

The module depends on JNA (`net.java.dev.jna:jna:…@aar`),
`kotlinx-coroutines-core` (Rust `async` functions are `suspend`) and
`androidx.annotation`, and ships R8 rules (`consumer-rules.pro`). The
package is `com.termoak.ffi`.

### Regenerating the bindings

```sh
scripts/generate-bindings.sh
```

It builds `termoak-ffi` for the current machine and runs the crate's own
`uniffi-bindgen` (same UniFFI version as the library). The architecture does
not matter: the bindings are the same.

## The API at a glance

| Object | Purpose |
|---|---|
| `TermoakCore(dataDir, vaultKeyB64)` | Entry point. One per app |
| `generateVaultKey()` | New vault key (stored in Keychain/Keystore) |
| `listHosts/getHost/saveHost/deleteHost`, and the same for groups, identities, keys, snippets, tunnels, known hosts and memories | Vault CRUD (synchronous, fast) |
| `generateKey`, `importKey`, `inspectPrivateKey`, `exportPrivateKey` | SSH keychain |
| `connect(hostId, auth)` → `SshSession` | Local SSH connection |
| `connectTerminal(hostId, cols, rows, auth, listener)` → `TerminalHandle` | Shortcut: connect and open a terminal |
| `TerminalScreen(cols, rows, scrollback)`: `feed`, `snapshot`, `key`, `character`, `paste`, `resize`, `scroll` | Terminal emulator (the desktop one): turns output into a screen ready to draw, and keystrokes into bytes |
| `SshSession.openTerminal`, `sftp*`, `exec`, `startForward*`, `detectOs`, `disconnect` | Terminals, SFTP, commands and tunnels over a connection |
| `login/register/logout/isLoggedIn/syncNow` | Server account and sync (with optional 2FA code and invitation) |
| `verificationRequired`, `verifyCode(url, email, code)`, `resendCode(url, email)` | Email verification with the six-digit code from the email (signs in) |
| `inviteInfo(url, token)` | Invitation details before signing up |
| `twoFactorStatus/setupTwoFactor/enableTwoFactor/disableTwoFactor`, `qrCode(text)` | Two-step verification (TOTP) with its QR code |
| `listTeams/createTeam/renameTeam/deleteTeam`, `listTeamMembers/addTeamMember/setTeamMemberRole/removeTeamMember/leaveTeam` | Teams |
| `shareServerSession(sessionId, target, control, expiresInMinutes)`, `SharedTerminal.inviteTeam` | Share with a user, a team or a link |
| `adminListUsers/adminCreateUser/adminUpdateUser/adminResetPassword/adminResetTwoFactor`, `adminCreateInvite/adminListInvites/adminRevokeInvite`, `adminAudit` | Server administration (administrators only) |
| `importSshConfig(text, options)`, `importSshConfigFile(path, options)` | Import an `ssh_config` (with a `dryRun` preview) |
| `completeCommand(hostId, os, line, limit)`, `recordCommand`, `clearCommandHistory` | Command autocomplete |
| `SshSession.detectOsInfo()` → `RemoteOs` | Host OS with version and package manager |
| `registerPushToken(platform, token, sandbox)`, `unregisterPushToken`, `sendTestPush` | Push notifications (APNs and FCM) |
| `serverSftpHome/List/Download/Upload/Mkdir/Rename/Delete`, `downloadRecording` | Files and recordings through the server, streamed with progress |
| `listServerSessions/openServerSession/attachServerSession/closeServerSession` | Persistent sessions |
| `joinSharedSession(serverUrl, token, listener)` | Join with an invitation link, without an account |
| `shareTerminal(terminal, title)` → `SharedTerminal` | Share a local terminal (relay) and invite people |
| `createAiTask/listAiTasks/getAiTask/sendAiMessage/cancelAiTask` | Background AI |
| `listPendingApprovals/decideApproval` | Approve or deny AI actions |
| `subscribeEvents(listener)` | Account events (AI, sessions) |
| `apiGet/apiPost/apiPut/apiPatch/apiDelete/apiRequest` | Any JSON endpoint of the API ([API.md](https://github.com/TermoakSSH/server/blob/main/docs/API.md)) with JSON as text |
| `initLogging(level, listener)` | Library logging to Logcat/`os_log` |

Conventions:

- Ids are `String` (UUID). Saving with an empty `id` creates a new record.
- Secrets do not travel inside records: they are passed separately with
  `SecretChange` (`keep`, `set(value:)`, `clear`), and `hasPassword` /
  `hasPrivateKey` tell whether one is stored.
- `syncMode` is `nil`/`null` when saving to keep the current one (`Synced`
  for new records); `DeviceOnly` means it never leaves the device.
- Unsigned integers: ports, columns and rows are `UInt32` in Swift and `UInt`
  in Kotlin (`22u`).
- Errors: a single error type, `TermoakError` in Swift and
  `TermoakException` in Kotlin, with variants to decide what to do
  (`NotLoggedIn`, `SessionExpired`, `TotpRequired`, `TotpInvalid`,
  `EmailNotVerified`, `HostKey`, `Auth`, `Network`, `Vault`…) and a message ready to show. In
  Swift, `TermoakKit` adds a helper that returns the message of any error;
  in Kotlin, use `e.message`.

## Swift

### Creating the core with the key in the Keychain

```swift
import TermoakKit
import Foundation
import Security

enum Vault {
    private static let service = "com.termoak"
    private static let account = "vault-key"

    /// Vault key: the one in the Keychain or a new one (this device only).
    static func key() throws -> String {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
        ]
        var result: CFTypeRef?
        if SecItemCopyMatching(query as CFDictionary, &result) == errSecSuccess,
           let data = result as? Data, let key = String(data: data, encoding: .utf8) {
            return key
        }
        let newKey = generateVaultKey()
        query.removeValue(forKey: kSecReturnData as String)
        query[kSecValueData as String] = Data(newKey.utf8)
        query[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status))
        }
        return newKey
    }
}

let folder = FileManager.default
    .urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
    .appendingPathComponent("Termoak", isDirectory: true)
let core = try TermoakCore(dataDir: folder.path, vaultKeyB64: try Vault.key())
```

### Hosts

```swift
let hosts = try core.listHosts()   // synchronous: fine on the main thread
let web = try core.saveHost(
    host: SshHost(label: "web-1", address: "web1.example.com",
                  settings: HostSettings(port: 22, username: "deploy")),
    password: .set(value: "password")
)
let key = try await core.generateKey(label: "iPhone", keyType: .ed25519,
                                     comment: "me@iphone", passphrase: nil,
                                     storePassphrase: false, syncMode: .deviceOnly)
print(key.publicKey)   // for authorized_keys
```

### Local terminal

`TerminalListener` receives the output; `AuthHandler` answers the
connection's questions. A single class can implement both. The protocols are
`Sendable`: mark the class `@unchecked Sendable` and hop to the main thread
to touch the UI.

```swift
final class TerminalModel: ObservableObject, TerminalListener, AuthHandler,
                           @unchecked Sendable {
    private var terminal: TerminalHandle?
    let emulator: TerminalEmulator   // e.g. SwiftTerm

    // Output (background thread, in order): copy and hop to the main thread.
    func onOutput(data: Data) {
        DispatchQueue.main.async { self.emulator.feed([UInt8](data)) }
    }

    func onStatus(status: TerminalStatus) {
        if case .closed(let code, let reason) = status {
            DispatchQueue.main.async { self.showClosed(code, reason) }
        }
    }

    // Questions (background thread): may block while the user decides.
    func onHostKey(host: String, port: UInt32, keyType: String, fingerprint: String) -> Bool {
        let semaphore = DispatchSemaphore(value: 0)
        var accept = false
        DispatchQueue.main.async {
            self.confirmFingerprint(host: host, fingerprint: fingerprint) { ok in
                accept = ok
                semaphore.signal()
            }
        }
        semaphore.wait()
        return accept
    }

    func onPrompt(request: AuthRequest) -> [String]? {
        // Same idea: a dialog with one field per `request.fields` (secure if !echo).
        // Returning nil cancels.
        nil
    }

    func connect(core: TermoakCore, hostId: String) async {
        do {
            terminal = try await core.connectTerminal(hostId: hostId, cols: 80, rows: 24,
                                                     auth: self, listener: self)
        } catch {
            showError(error.localizedDescription)
        }
    }

    // From the emulator:
    func type(_ bytes: [UInt8]) { try? terminal?.write(data: Data(bytes)) }
    func resize(cols: Int, rows: Int) {
        try? terminal?.resize(cols: UInt32(cols), rows: UInt32(rows))
    }

    // When leaving the screen: the library retains the listener until the
    // terminal closes, so close it.
    func close() { terminal?.closeTerminal(); terminal = nil }
}
```

SFTP over the same connection:

```swift
let session = terminal.session()
let files = try await session.sftpList(path: try await session.sftpHome())
let destination = FileManager.default.temporaryDirectory.appendingPathComponent("app.log")
_ = try await session.sftpDownload(remotePath: "/var/log/app.log",
                                   localPath: destination.path, listener: nil)
```

### Server: login, sync and a persistent session

```swift
try core.setDeviceName(name: UIDevice.current.name)   // shown in "Devices"
try await core.login(url: "https://termoak.example.com",
                     email: "ana@example.com", password: password)
let report = try await core.syncNow()   // pushed / pulled / rev

let session = try await core.openServerSession(hostId: web.id, cols: 80, rows: 24,
                                               title: "deploy", record: nil)
let view = try await core.attachServerSession(sessionId: session.id, listener: model)
```

```swift
final class ServerSessionModel: ServerTerminalListener, @unchecked Sendable {
    var session: ServerTerminalHandle?

    func onEvent(event: ServerTerminalEvent) {
        DispatchQueue.main.async {
            switch event {
            case .output(let data): self.emulator.feed([UInt8](data))
            case .resync: self.emulator.reset()          // the full scrollback follows
            case .prompt(let prompt): self.ask(prompt)
            case .status(let state): self.state = state
            case .presence(let viewers): self.viewers = viewers
            case .closed: self.session = nil
            default: break
            }
        }
    }

    func ask(_ p: ServerPrompt) {
        // hostkey: accept the fingerprint or not; otherwise one text per field.
        if p.kind == "hostkey" {
            try? session?.answerPrompt(promptId: p.promptId, accept: true, answers: nil)
        }
    }
}
```

`detach()` (or dropping the object) only detaches the screen: the session
stays alive on the server. `closeSession()` closes it.

### Two-step verification, invitations and teams

```swift
// Login: if the account has 2FA, the first call fails with .TotpRequired.
do {
    try await core.login(url: url, email: email, password: password)
} catch TermoakError.TotpRequired {
    let code = await askForCode()          // 6 digits or a recovery code
    try await core.login(url: url, email: email, password: password, totpCode: code)
}

// Enable 2FA from Settings.
let setup = try await core.setupTwoFactor()
if let qr = qrCode(text: setup.otpauthUrl) { drawQR(qr.size, qr.modules) }
let recoveryCodes = try await core.enableTwoFactor(code: codeFromTheApp)

// Sign up with an invitation (the `termoak://invite?server=…&token=…` link).
let info = try await inviteInfo(url: server, token: code)   // email, team
try await core.register(url: server, email: email, name: name,
                        password: password, invite: code)

// Servers that require a verified email (`features.email_verification` in
// serverInfo): a new account gets a six-digit code by email. Until it is
// entered, everything but the account itself fails with .EmailNotVerified.
try await core.register(url: server, email: email, name: name, password: password)
if try await core.verificationRequired() {
    // "Check your email" screen: code field (numeric, one-time-code),
    // "Resend code" (at most once a minute) and "Use a different email".
    do {
        try await core.verifyCode(url: server, email: email, code: typedCode)  // signs in
    } catch TermoakError.Invalid {
        // Wrong or expired (5 wrong tries use a code up): ask for another.
        try await core.resendCode(url: server, email: email)
    }
}
// The same after `login` (the server emails a new code if the last one
// expired), or whenever a call fails with .EmailNotVerified (the email is
// `serverUser()`).

// Share a persistent session with a team.
let team = try await core.createTeam(name: "Ops")
_ = try await core.addTeamMember(teamId: team.id, email: "beto@example.com", role: .member)
_ = try await core.shareServerSession(sessionId: session.id,
                                      target: .team(teamId: team.id),
                                      control: false, expiresInMinutes: nil)
```

Whoever leaves a team (or is removed from it) immediately loses access to
the sessions shared with it.

### Push notifications

The server notifies you even when the app is closed: AI approvals, finished
tasks, sessions shared with you, pending questions in your sessions and new
teams (see [DEPLOYMENT.md](https://github.com/TermoakSSH/server/blob/main/docs/DEPLOYMENT.md#push-notifications) to set it up).

```swift
// AppDelegate: after asking for permission with UNUserNotificationCenter.
func application(_ app: UIApplication,
                 didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
    let hex = deviceToken.map { String(format: "%02x", $0) }.joined()
    Task {
        #if DEBUG
        let sandbox = true
        #else
        let sandbox = false
        #endif
        _ = try? await core.registerPushToken(platform: .apns, token: hex, sandbox: sandbox)
    }
}

// When the notification is tapped: `userInfo["termoak"]` carries `type` and the ids.
let data = response.notification.request.content.userInfo["termoak"] as? [String: String]
if data?["type"] == "ai_approval", let task = data?["task_id"] { openApproval(task) }
```

```kotlin
// FirebaseMessagingService
override fun onNewToken(token: String) {
    scope.launch { core.registerPushToken(PushPlatform.FCM, token, false) }
}
override fun onMessageReceived(msg: RemoteMessage) {
    when (msg.data["type"]) {
        "ai_approval" -> openApproval(msg.data["task_id"]!!)
        "session_shared" -> openSession(msg.data["session_id"]!!)
    }
}
```

On Android, create the `termoak` notification channel. Call
`unregisterPushToken()` when signing out. `sendTestPush()` helps check the
setup.

### Files through the server

For hosts the phone cannot reach (only the server has a network path to
them), the server does the SFTP and the app receives the file as a stream,
straight to disk:

```swift
let destination = FileManager.default.temporaryDirectory.appendingPathComponent("app.log").path
let bytes = try await core.serverSftpDownload(hostId: web.id, remotePath: "/var/log/app.log",
                                              localPath: destination, listener: progress)
try await core.downloadRecording(sessionId: session.id, localPath: castPath, listener: nil)
```

While downloading, data is written to `<destination>.part`; if the transfer
is interrupted, no half-written file is left under the final name.

### Importing `ssh_config` and autocomplete

```swift
// Preview, then the real import (repeating it does not duplicate anything).
let preview = try core.importSshConfig(text: content,
                                       options: SshConfigImportOptions(dryRun: true))
let report = try core.importSshConfig(text: content,
                                      options: SshConfigImportOptions(group: "Imported"))

// While typing in the terminal (fast, can be called on every keystroke):
let suggestions = try core.completeCommand(hostId: host.id, os: host.os,
                                           line: currentLine, limit: 5)
// On accept, send `suggestions[0].insert` to the terminal.
// On Enter, save it to the local history (never synced):
_ = try core.recordCommand(hostId: host.id, command: currentLine)
```

The app keeps `currentLine` (what was typed since the last Enter).
Suggestions come from this device's history, one-line snippets and a
dictionary aware of the host's OS (`apt` on Debian/Ubuntu, `dnf` on
Fedora/RHEL, `apk` on Alpine…). Commands that seem to contain secrets, or
that start with a space, are not saved.

### Background AI and approvals

```swift
let task = try await core.createAiTask(request: AiTaskRequest(
    prompt: "Find out why nginx returns 502 on web-1",
    mode: .ask, hostIds: [web.id]))

for approval in try await core.listPendingApprovals() {
    // approval.summary: "touch /etc/nginx/…", approval.inputJson: arguments
    try await core.decideApproval(taskId: approval.taskId, approvalId: approval.id,
                                  approve: true, always: false)
}
let result = try await core.getAiTask(taskId: task.id).result
```

Foreground events:

```swift
final class Notices: ServerEventListener, @unchecked Sendable {
    func onEvent(eventJson: String) { /* JSONDecoder: type = hello | ai | session | lagged */ }
    func onClosed(reason: String?) { /* subscribe again with retries */ }
}
let subscription = try await core.subscribeEvents(listener: Notices())
```

## Kotlin

### Creating the core with the key protected by the Keystore

The Keystore does not store arbitrary values: create an AES key in it that
encrypts the vault key, and store the result in the preferences.

```kotlin
import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import com.termoak.ffi.*
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

object Vault {
    private const val ALIAS = "termoak-vault"

    private fun keystoreKey(): SecretKey {
        val ks = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(ALIAS, null) as? SecretKey)?.let { return it }
        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        gen.init(
            KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .build(),
        )
        return gen.generateKey()
    }

    fun key(context: Context): String {
        val prefs = context.getSharedPreferences("vault", Context.MODE_PRIVATE)
        prefs.getString("key", null)?.let { stored ->
            val data = Base64.decode(stored, Base64.NO_WRAP)
            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, keystoreKey(), GCMParameterSpec(128, data, 0, 12))
            return String(cipher.doFinal(data, 12, data.size - 12))
        }
        val newKey = generateVaultKey()
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, keystoreKey())
        val encrypted = cipher.iv + cipher.doFinal(newKey.toByteArray())
        prefs.edit().putString("key", Base64.encodeToString(encrypted, Base64.NO_WRAP)).apply()
        return newKey
    }
}

val core = TermoakCore(File(context.filesDir, "termoak").path, Vault.key(context))
```

### Hosts

```kotlin
val hosts = core.listHosts()
val web = core.saveHost(
    SshHost(label = "web-1", address = "web1.example.com",
            settings = HostSettings(port = 22u, username = "deploy")),
    SecretChange.Set("password"),
)
val key = core.generateKey("Pixel", KeyType.ED25519, "me@pixel", null, false, SyncMode.DEVICE_ONLY)
```

### Local terminal

```kotlin
class TerminalViewModel(private val core: TermoakCore) : ViewModel(), TerminalListener, AuthHandler {
    private var terminal: TerminalHandle? = null

    // The terminal's own background thread, in order: return quickly.
    override fun onOutput(data: ByteArray) {
        viewModelScope.launch(Dispatchers.Main) { emulator.append(data) }
    }

    override fun onStatus(status: TerminalStatus) {
        if (status is TerminalStatus.Closed) {
            viewModelScope.launch(Dispatchers.Main) { showClosed(status.exitCode, status.reason) }
        }
    }

    // Background thread: may block while the user decides.
    override fun onHostKey(host: String, port: UInt, keyType: String, fingerprint: String): Boolean =
        runBlocking { dialogs.confirmFingerprint(host, fingerprint) }   // suspends until answered

    override fun onPrompt(request: AuthRequest): List<String>? =
        runBlocking { dialogs.ask(request) }                           // null = cancel

    fun connect(hostId: String) = viewModelScope.launch {
        try {
            terminal = core.connectTerminal(hostId, 80u, 24u, this@TerminalViewModel, this@TerminalViewModel)
        } catch (e: TermoakException.HostKey) {
            showError(e.message)   // the server key changed or was rejected
        } catch (e: TermoakException) {
            showError(e.message)
        }
    }

    fun type(bytes: ByteArray) { terminal?.write(bytes) }
    fun resize(cols: Int, rows: Int) { terminal?.resize(cols.toUInt(), rows.toUInt()) }

    override fun onCleared() {
        terminal?.closeTerminal()   // closes the terminal and releases this listener
        terminal?.close()           // frees the native object (AutoCloseable)
    }
}
```

### Server, sessions and AI

```kotlin
core.setDeviceName("${Build.MANUFACTURER} ${Build.MODEL}")   // shown in "Devices"
try {
    core.login("https://termoak.example.com", "ana@example.com", password)
} catch (e: TermoakException.TotpRequired) {
    core.login("https://termoak.example.com", "ana@example.com", password, askForCode())
}
val report = core.syncNow()

val session = core.openServerSession(web.id, 80u, 24u, "deploy", null)
val view = core.attachServerSession(session.id, object : ServerTerminalListener {
    override fun onEvent(event: ServerTerminalEvent) {
        when (event) {
            is ServerTerminalEvent.Output -> emulator.append(event.data)
            is ServerTerminalEvent.Resync -> emulator.reset()     // the full scrollback follows
            is ServerTerminalEvent.Prompt -> askForAnswer(event.prompt)
            is ServerTerminalEvent.Status -> state.value = event.state
            is ServerTerminalEvent.Closed -> onClosed()
            else -> Unit
        }
    }
})
// Answer a question (fingerprint: accept; 2FA/password: answers).
view.answerPrompt(prompt.promptId, true, null)

val task = core.createAiTask(AiTaskRequest(prompt = "Free up space in /var/log on web-1",
                                           mode = AiPermissionMode.ASK, hostIds = listOf(web.id)))
core.listPendingApprovals().forEach { a ->
    core.decideApproval(a.taskId, a.id, approve = true, always = false)
}

// Teams, import and autocomplete.
val team = core.createTeam("Ops")
core.shareServerSession(session.id, ShareTarget.Team(team.id), control = false, expiresInMinutes = null)
val importReport = core.importSshConfig(text, SshConfigImportOptions(dryRun = false, group = "Imported"))
val suggestions = core.completeCommand(host.id, host.os, currentLine, 5u)

val events = core.subscribeEvents(object : ServerEventListener {
    override fun onEvent(eventJson: String) {
        val v = JSONObject(eventJson)
        if (v.getString("type") == "ai" &&
            v.getJSONObject("event").optString("type") == "approval_requested") notifyApproval(v)
    }
    override fun onClosed(reason: String?) { scheduleReconnect() }
})
```

## Threads and lifecycle

- **Own runtime.** The library has its own tokio runtime (2-4 threads). The
  app does not have to manage anything.
- **Synchronous functions** (vault CRUD, `write`, `resize`…): fast; they can
  be called from the main thread.
- **`async` functions** (network, SSH, key generation): `async throws` in
  Swift, `suspend` in Kotlin. Cancelling the `Task` or the coroutine aborts
  the operation in Rust.
- **Callbacks.** Always arrive on background threads, never on the main
  thread:
  - `TerminalListener` and `ServerTerminalListener`: one thread per terminal,
    in order and one at a time. Output is grouped in chunks of up to 64 KiB.
    If the app falls behind, it gets `ESC c` (local terminal) or `Resync`
    (server session) followed by the full scrollback.
  - `AuthHandler`: each question on its own thread; it **may block** while
    the dialog is shown. The fingerprint must be confirmed within about
    30 s or the SSH handshake times out.
  - `TransferListener` and `LogListener`: on runtime threads; they must
    return right away.
- **Releasing objects.** In Swift they are released when the last reference
  goes away; in Kotlin with `close()` (or `use {}`) or, later, by the garbage
  collector. Dropping a `TerminalHandle` closes its terminal; dropping an
  `SshSession` (and everything hanging from it) closes the connection;
  dropping a `ServerTerminalHandle` only detaches.
- **Reference cycles.** Rust retains a terminal's listener until it closes.
  If the listener is the view model itself and it holds the
  `TerminalHandle`, call `closeTerminal()` when leaving the screen.
- **Background.** iOS suspends the app shortly after you leave it and
  Android may do so: local SSH connections drop. For long jobs, use a server
  session (or, on Android, a *foreground service* that keeps the app alive).

## Security

- **Vault key.** 256 bits generated with `generateVaultKey()`. It is stored
  in the Keychain (`kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`) or
  encrypted with an Android Keystore key, never in plain text. If the key
  does not match the database, `TermoakCore(...)` fails with `Vault`: nothing
  is overwritten.
- **What is encrypted.** Passwords, private keys, passphrases and the server
  tokens are encrypted with the vault key (XChaCha20-Poly1305). Labels,
  addresses and other non-secret data are stored in plain text in the
  database: protect the folder with iOS data protection, and keep the
  database and the key out of cloud backups (the key belongs to this device,
  so the backup could not be opened; synced data is recovered from the
  server).
- **Only on this device.** With `syncMode = DeviceOnly`, a host or a key (and
  its secrets) is never sent to the server. Use it, for example, for the
  phone's own SSH key.
- **Known hosts.** The first connection asks about the fingerprint
  (`onHostKey`). If the key of a known host changes, the connection fails
  with `HostKey` without asking. To accept the new one, delete the old entry
  (`deleteKnownHost`).
- **TLS.** The connection to the server uses rustls with the Mozilla root
  certificates bundled in the library.
- **Logging.** `initLogging` never writes secrets; even so, do not enable
  `Trace` in released builds.

## Known limitations

- `apiRequest` and friends only work for JSON endpoints; for files use
  `serverSftp*` and `downloadRecording`.
- No SSH agent on mobile (there is no `SSH_AUTH_SOCK`); keys come from the
  vault.
