#!/usr/bin/env bash
# Builds and publishes the releases of this repository without GitHub
# Actions:
#
#   component   version in                          tag          publishes
#   cli         crates/termoak-cli/Cargo.toml       cli-vX.Y.Z   the `termoak` CLI (Linux, Windows, macOS)
#   ffi         Cargo.toml ([workspace.package])    ffi-vX.Y.Z   prebuilt mobile libraries (Android .so,
#                                                                iOS xcframework) and their bindings
#
# The libraries are not released as packages: the server and the desktop app
# depend on the `vX.Y.Z` git tag of this repository (the [workspace.package]
# version) and the mobile apps include it as a git submodule. After bumping
# that version and pushing: git tag vX.Y.Z && git push origin vX.Y.Z
#
#   scripts/release-local.sh status
#   scripts/release-local.sh version <cli|ffi> [X.Y.Z]
#   scripts/release-local.sh build cli [linux] [windows] [macos]
#   scripts/release-local.sh build ffi
#   scripts/release-local.sh publish <cli|ffi>
#   scripts/release-local.sh deploy cli
#   scripts/release-local.sh download cli <run-id>
#
# status shows each component's version, its latest tag and how many commits
# touched it since then: what has unreleased changes.
#
# version shows a component's version or changes it (and Cargo.lock).
#
# build compiles the version in the component's manifest into dist/<component>/:
#   linux    x86_64 and aarch64
#   windows  x86_64, with mingw-w64 from Linux
#   macos    Apple Silicon; only on a Mac
# Without platforms: linux and windows (plus macos on a Mac). linux and
# windows are built in Docker (scripts/builder.Dockerfile, Ubuntu 22.04) so
# they run on Ubuntu 22.04+ and Debian 12+; with DOCKER=0 they are built on
# this machine (which needs what that Dockerfile installs).
# `build ffi` builds the Android libraries (arm64-v8a, armeabi-v7a, x86_64) in
# the scripts/android-builder.Dockerfile image and, on a Mac, the iOS
# xcframework (scripts/build-ios.sh).
#
# publish creates the <component>-vX.Y.Z release with the contents of
# dist/<component>/, using the GitHub API (curl, no `gh`). It is created as a
# draft and published once all files are uploaded. If the release already
# exists, the files are added to it.
# The CLI release is the one marked as "Latest" on GitHub.
#
# deploy installs the CLI from dist/ (Linux) on this machine, in /usr/local/bin.
#
# download puts into dist/cli/ the binaries of a release-cli.yml run that did
# not get to publish (the id is in the run's URL).
#
# Variables:
#   GITHUB_TOKEN  GitHub token (publish and download). If unset, it is read
#                 from ~/.config/termoak/github-token. Fine-grained, with access to
#                 the TermoakSSH repositories, Contents: Read and write (and
#                 Actions: Read for download)
#   REPO          owner/repository (default: TermoakSSH/core)
#   COMMIT        commit to tag (default: HEAD)
#   VERSION       version for download and publish (default: the manifest's)
#
# Compatible with macOS's bash 3.2.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

die() { echo "error: $*" >&2; exit 1; }
say() { printf '\n==> %s\n' "$*"; }

COMPONENTS="cli ffi"

# --- components ---------------------------------------------------------------

manifest_of() { # component
  case "$1" in
    cli) echo crates/termoak-cli/Cargo.toml ;;
    ffi) echo Cargo.toml ;;
    *) die "unknown component: ${1:-} (cli or ffi)" ;;
  esac
}

title_of() {
  case "$1" in
    cli) echo CLI ;;
    ffi) echo "Mobile libraries" ;;
  esac
}

# Code each component depends on (for `status`).
paths_of() {
  local libs="crates/termoak-core crates/termoak-ssh crates/termoak-client"
  case "$1" in
    cli) echo "crates/termoak-cli $libs Cargo.lock" ;;
    ffi) echo "crates/termoak-ffi $libs bindings Cargo.toml Cargo.lock scripts/build-android.sh scripts/build-ios.sh scripts/android-builder.Dockerfile" ;;
  esac
}

# The first `version = ` line: the CLI's [package], or [workspace.package]
# (the version of every library) in the root Cargo.toml.
version_of() { # component
  local file v
  file="$(manifest_of "$1")"
  v="$(sed -n 's/^version = "\(.*\)"/\1/p' "$file" | head -1)"
  [[ -n "$v" ]] || die "$file has no version = \"X.Y.Z\" line"
  echo "$v"
}

# A component's latest published tag.
last_tag_of() { git tag -l "$1-v*" --sort=-v:refname | head -1; }

# Component and version from the command line. In build, `version` and `tag`
# always come from the manifest; in download and publish they can be changed
# with VERSION (e.g. for binaries from an earlier release.yml run).
select_component() { # component command
  component="${1:-}"
  [[ -n "$component" ]] || die "missing component: cli or ffi"
  manifest_of "$component" >/dev/null
  version="$(version_of "$component")"
  if [[ -n "${VERSION:-}" && "$2" != build ]]; then
    version="${VERSION#v}"
  fi
  tag="$component-v$version"
  dist="$root/dist/$component"
}

# Inside Docker the binaries go to another folder so they don't mix with the
# ones built on the host (different glibc).
if [[ -n "${BUILD_TARGET_DIR:-}" ]]; then
  root_target="$BUILD_TARGET_DIR/root"
else
  root_target="$root/target"
fi

# The build image already has them installed (and rustup is read-only there).
add_targets() {
  [[ -n "${TERMOAK_BUILDER:-}" ]] || rustup target add "$@" >/dev/null
}

# --- status and version -------------------------------------------------------

cmd_status() {
  git fetch -q --tags origin 2>/dev/null || true
  printf '%-9s %-9s %-16s %s\n' component version 'latest tag' 'commits since'
  local c v last n note
  for c in $COMPONENTS; do
    v="$(version_of "$c")"
    last="$(last_tag_of "$c")"
    note=""
    if [[ -z "$last" ]]; then
      last="-"
      n="$(git rev-list --count HEAD)"
    else
      # shellcheck disable=SC2046
      n="$(git rev-list --count "$last..HEAD" -- $(paths_of "$c"))"
    fi
    if [[ "$n" != 0 ]] && git rev-parse -q --verify "refs/tags/$c-v$v" >/dev/null; then
      note="  (v$v already published: bump the version before publishing)"
    fi
    printf '%-9s %-9s %-16s %s%s\n' "$c" "$v" "$last" "$n" "$note"
  done
}

cmd_version() { # component [X.Y.Z]
  select_component "${1:-}" version
  local new="${2:-}" file
  if [[ -z "$new" ]]; then
    echo "$version"
    return
  fi
  new="${new#v}"
  [[ "$new" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]] || die "\"$new\" is not an X.Y.Z version"
  [[ "$new" != "$version" ]] || die "$component is already at $new"
  file="$(manifest_of "$component")"
  # Only the first `version = ` line.
  awk -v v="$new" '!done && /^version = "/ { print "version = \"" v "\""; done = 1; next } { print }' \
    "$file" >"$file.tmp" && mv "$file.tmp" "$file"
  if [[ "$component" == ffi ]]; then
    cargo update -q --workspace
    say "libraries: $version → $new ($file and Cargo.lock). Once pushed, tag them: git tag v$new && git push origin v$new"
  else
    cargo update -q -p termoak-cli
    say "$component: $version → $new ($file and Cargo.lock)"
  fi
}

# --- build --------------------------------------------------------------------

# termoak-<component>-vX.Y.Z-<name>.tar.gz (.zip on Windows).
package_bin() { # rust-target name
  local target="$1" name="$2" ext="" bin work d
  [[ "$target" == *windows* ]] && ext=".exe"
  bin=termoak
  say "$(title_of "$component") $version: $name"
  cargo build --release --locked --target "$target" --target-dir "$root_target" -p "termoak-$component"
  d="termoak-$component-v$version-$name"
  work="$(mktemp -d)"
  mkdir "$work/$d"
  cp "$root_target/$target/release/$bin$ext" README.md "$work/$d/"
  if [[ -n "$ext" ]]; then
    (cd "$work" && zip -qr "$dist/$d.zip" "$d")
  else
    tar czf "$dist/$d.tar.gz" -C "$work" "$d"
  fi
  rm -rf "$work"
}

build_linux() {
  export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER="${CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER:-aarch64-linux-gnu-gcc}"
  export CC_aarch64_unknown_linux_gnu="${CC_aarch64_unknown_linux_gnu:-aarch64-linux-gnu-gcc}"
  export AR_aarch64_unknown_linux_gnu="${AR_aarch64_unknown_linux_gnu:-aarch64-linux-gnu-ar}"
  add_targets x86_64-unknown-linux-gnu aarch64-unknown-linux-gnu
  package_bin x86_64-unknown-linux-gnu linux-x86_64
  package_bin aarch64-unknown-linux-gnu linux-aarch64
}

build_windows() {
  add_targets x86_64-pc-windows-gnu
  package_bin x86_64-pc-windows-gnu windows-x86_64
}

build_macos() {
  [[ "$(uname -s)" == Darwin ]] || die "macOS can only be built on a Mac"
  add_targets aarch64-apple-darwin
  package_bin aarch64-apple-darwin macos-aarch64
}

# Builds linux and windows inside the scripts/builder.Dockerfile image.
build_in_docker() { # platforms...
  command -v docker >/dev/null || die "Docker is missing (or use DOCKER=0 with the tools installed)"
  say "Build image (Ubuntu 22.04)"
  docker build --platform linux/amd64 -t termoak-builder - <scripts/builder.Dockerfile
  # Run as this machine's user so dist/ and target/ stay owned by it.
  # The cargo registry is kept in target/builder so it isn't downloaded every time.
  docker run --rm --platform linux/amd64 --user "$(id -u):$(id -g)" \
    -v "$root:/src" -w /src -e HOME=/tmp \
    -e BUILD_TARGET_DIR=/src/target/builder -e CARGO_HOME=/src/target/builder/cargo \
    termoak-builder scripts/release-local.sh build "$component" "$@"
}

# Mobile libraries: the Android .so files (in the scripts/android-builder.Dockerfile
# image) and, on a Mac, the iOS xcframework, plus the bindings that go with them.
build_ffi() {
  local abis=(arm64-v8a armeabi-v7a x86_64) targets=() abi
  if [[ "$(uname -s)" == Darwin ]]; then
    say "Mobile libraries $version: iOS xcframework"
    scripts/build-ios.sh release
    (cd bindings/swift && zip -qry "$dist/termoak-ffi-v$version-ios-xcframework.zip" termoak_ffiFFI.xcframework)
  fi
  if command -v docker >/dev/null; then
    say "Android build image"
    docker build -q -t termoak-android-builder - <scripts/android-builder.Dockerfile >/dev/null
    for abi in "${abis[@]}"; do targets+=(-t "$abi"); done
    say "Mobile libraries $version: Android (${abis[*]})"
    # The cargo registry is kept in target/android.
    docker run --rm -v "$root:/src" -w /src \
      -e CARGO_HOME=/src/target/android/cargo-home -e CARGO_TARGET_DIR=/src/target/android \
      termoak-android-builder bash -c "set -e
        export PATH=/usr/local/cargo/bin:\$PATH
        rm -rf bindings/kotlin/src/main/jniLibs
        cargo ndk ${targets[*]} --platform 26 -o bindings/kotlin/src/main/jniLibs \
          build -p termoak-ffi --lib --release --locked"
    (cd bindings/kotlin/src/main && zip -qr "$dist/termoak-ffi-v$version-android-jniLibs.zip" jniLibs)
  else
    echo "Without Docker the Android libraries are not built." >&2
  fi
  (cd bindings && zip -qr "$dist/termoak-ffi-v$version-bindings.zip" kotlin swift/Package.swift swift/Sources \
    -x 'kotlin/src/main/jniLibs/*' -x 'kotlin/build/*')
}

cmd_build() { # component [platforms...]
  select_component "${1:-}" build
  shift
  if [[ "$component" == ffi ]]; then
    rm -rf "$dist"
    mkdir -p "$dist"
    echo "$tag" >"$dist/.version"
    build_ffi
    say "Done: $tag in dist/ffi/"
    ls -l "$dist"
    return
  fi
  local platforms=("$@") p in_docker=() native=()
  if [[ ${#platforms[@]} -eq 0 ]]; then
    platforms=(linux windows)
    if [[ "$(uname -s)" == Darwin ]]; then
      if command -v docker >/dev/null; then
        platforms=(macos "${platforms[@]}")
      else
        echo "Without Docker on this Mac, only macOS is built." >&2
        platforms=(macos)
      fi
    fi
  fi
  for p in "${platforms[@]}"; do
    case "$p" in
      linux | windows)
        if [[ -n "${TERMOAK_BUILDER:-}" || "${DOCKER:-1}" == 0 ]]; then native+=("$p"); else in_docker+=("$p"); fi ;;
      macos) native+=("$p") ;;
      *) die "unknown platform: $p (linux, windows or macos)" ;;
    esac
  done

  # The outer call empties dist/<component>/; the one inside Docker adds to it.
  if [[ -z "${TERMOAK_BUILDER:-}" ]]; then
    rm -rf "$dist"
    mkdir -p "$dist"
    echo "$tag" >"$dist/.version"
  fi
  if [[ ${#in_docker[@]} -gt 0 ]]; then build_in_docker "${in_docker[@]}"; fi
  for p in ${native[@]+"${native[@]}"}; do "build_$p"; done

  if [[ -z "${TERMOAK_BUILDER:-}" ]]; then
    say "Done: $tag in dist/$component/"
    ls -l "$dist"
  fi
}

# --- deploy -------------------------------------------------------------------

cmd_deploy() { # cli
  select_component "${1:-}" deploy
  [[ "$component" == cli ]] || die "deploy is for the CLI"
  [[ "$(uname -s)" == Linux ]] || die "deploy only installs on Linux"
  [[ "$(cat "$dist/.version" 2>/dev/null)" == "$tag" ]] ||
    die "dist/cli/ does not hold $tag: run scripts/release-local.sh build cli first"
  local arch archive work sudo=""
  arch="$(uname -m)"
  if [[ "$arch" == arm64 ]]; then arch=aarch64; fi
  archive="$dist/termoak-cli-v$version-linux-$arch.tar.gz"
  [[ -f "$archive" ]] || die "$(basename "$archive") is not in dist/cli/"
  [[ "$(id -u)" == 0 ]] || sudo=sudo
  work="$(mktemp -d)"
  tar xzf "$archive" -C "$work" --strip-components=1
  "$work/termoak" --version >/dev/null || die "the binary in $(basename "$archive") does not run on this machine"
  $sudo install -m 755 "$work/termoak" /usr/local/bin/termoak
  rm -rf "$work"
  say "Installed /usr/local/bin/termoak ($(/usr/local/bin/termoak --version))"
}

# --- GitHub API (curl) --------------------------------------------------------

github_setup() {
  command -v curl >/dev/null || die "curl is missing"
  command -v python3 >/dev/null || die "python3 is missing (needed to read GitHub's JSON responses)"
  local file="${XDG_CONFIG_HOME:-$HOME/.config}/termoak/github-token"
  github_token="${GITHUB_TOKEN:-}"
  if [[ -z "$github_token" && -f "$file" ]]; then
    github_token="$(tr -d '[:space:]' <"$file")"
  fi
  # Otherwise, the login of the GitHub CLI if it is installed (`gh auth login`).
  if [[ -z "$github_token" ]] && command -v gh >/dev/null; then
    github_token="$(gh auth token 2>/dev/null || true)"
  fi
  [[ -n "$github_token" ]] ||
    die "the GitHub token is missing: GITHUB_TOKEN, $file or \`gh auth login\`"
  # This repository; REPO=owner/repository publishes somewhere else (a fork).
  repo="${REPO:-TermoakSSH/core}"
  [[ "$repo" == */* ]] || die "cannot tell which repository this is: set REPO=owner/repository"
}

# Calls the API. Leaves the response in api_body and the HTTP status in api_status.
github() { # method path-or-url [curl arguments...]
  local method="$1" url="$2" out
  shift 2
  [[ "$url" == https://* ]] || url="https://api.github.com$url"
  # -L: GitHub redirects downloads to its storage (curl does not forward the
  # token to another domain).
  out="$(curl -sS -L -X "$method" -w '\n%{http_code}' \
    -H "Authorization: Bearer $github_token" -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" "$@" "$url")" || die "could not connect to GitHub"
  api_status="${out##*$'\n'}"
  api_body="${out%$'\n'*}"
}
# Like github(), but stops if GitHub answers with an error.
github_ok() { # what-we-were-doing method path [curl arguments...]
  local what="$1"
  shift
  github "$@"
  if [[ "$api_status" != 2* ]]; then
    printf '%s\n' "$api_body" >&2
    die "GitHub answered $api_status when trying to $what"
  fi
}
# Python expression over the JSON response (in `d`).
json() {
  printf '%s' "$api_body" | python3 -c "import json, sys; d = json.load(sys.stdin); v = $1; print('' if v is None else v)"
}
# JSON object from key value pairs. `draft` is a boolean; everything else is
# a string (make_latest too: the API expects "true" or "false").
json_object() {
  python3 -c '
import json, sys
a = sys.argv[1:]
print(json.dumps({k: (v == "true") if k == "draft" else v for k, v in zip(a[::2], a[1::2])}))' "$@"
}

# --- download -----------------------------------------------------------------

cmd_download() { # component id
  select_component "${1:-}" download
  local run="${2:-}" work
  [[ -n "$run" ]] || die "missing run id (the number in its Actions URL)"
  command -v unzip >/dev/null || die "unzip is missing"
  github_setup
  github_ok "list the artifacts of run $run" GET "/repos/$repo/actions/runs/$run/artifacts?per_page=100"
  local urls url
  urls="$(json "'\\n'.join(a['archive_download_url'] for a in d['artifacts'] if a['name'].startswith('$component-') and not a['expired'])")"
  [[ -n "$urls" ]] || die "that run has no $component artifacts (or they expired)"
  work="$(mktemp -d)"
  while IFS= read -r url; do
    curl -fsSL -H "Authorization: Bearer $github_token" -o "$work/a.zip" "$url" ||
      die "could not download an artifact"
    unzip -q -o "$work/a.zip" -d "$work/files"
    rm -f "$work/a.zip"
  done <<<"$urls"
  find "$work" -type f -name "*v$version*" | grep -q . ||
    die "that run is not for $tag: set its version with VERSION=X.Y.Z"
  rm -rf "$dist"
  mkdir -p "$dist"
  find "$work" -type f -exec mv {} "$dist/" \;
  rm -rf "$work"
  echo "$tag" >"$dist/.version"
  say "Artifacts of $tag in dist/$component/"
  ls -l "$dist"
}

# --- publish ------------------------------------------------------------------

cmd_publish() { # component
  select_component "${1:-}" publish
  local commit existing=0 file files=() prev latest id asset_id
  [[ -z "${2:-}" ]] || die "unknown option: $2"
  [[ "$(cat "$dist/.version" 2>/dev/null)" == "$tag" ]] ||
    die "dist/$component/ does not hold $tag: run scripts/release-local.sh build $component first"
  github_setup

  github GET "/repos/$repo/releases/tags/$tag"
  if [[ "$api_status" == 200 ]]; then
    existing=1
    id="$(json 'd["id"]')"
    say "Release $tag already exists: adding the files"
  elif [[ "$api_status" != 404 ]]; then
    printf '%s\n' "$api_body" >&2
    die "GitHub answered $api_status when looking up release $tag (does the token have access to the repository?)"
  else
    commit="${COMMIT:-$(git rev-parse HEAD)}"
    git fetch -q --tags origin 2>/dev/null || true
    [[ -n "$(git branch -r --contains "$commit" 2>/dev/null)" ]] ||
      die "commit $commit is not on GitHub: push it first (git push)"
  fi


  for file in "$dist"/*; do
    [[ -f "$file" ]] && files+=("$file")
  done
  [[ ${#files[@]} -gt 0 ]] || die "nothing to publish in dist/$component/"

  if [[ $existing == 0 ]]; then
    # An earlier attempt that failed halfway leaves a draft: reuse it.
    github_ok "look for drafts" GET "/repos/$repo/releases?per_page=100"
    id="$(json "next((r['id'] for r in d if r['draft'] and r['tag_name'] == '$tag'), None)")"
  fi
  if [[ $existing == 0 && -n "$id" ]]; then
    say "Found a draft of $tag from an earlier attempt: completing it"
  elif [[ $existing == 0 ]]; then
    # Notes since the previous version of this same component.
    prev="$(last_tag_of "$component")"
    if [[ -n "$prev" && "$prev" != "$tag" ]]; then
      github_ok "generate the notes" POST "/repos/$repo/releases/generate-notes" \
        -d "$(json_object tag_name "$tag" target_commitish "$commit" previous_tag_name "$prev")"
    else
      github_ok "generate the notes" POST "/repos/$repo/releases/generate-notes" \
        -d "$(json_object tag_name "$tag" target_commitish "$commit")"
    fi
    say "Creating release $tag in $repo ($commit) as a draft"
    github_ok "create the release" POST "/repos/$repo/releases" \
      -d "$(json_object tag_name "$tag" target_commitish "$commit" \
        name "$(title_of "$component") $version" body "$(json 'd["body"]')" draft true)"
    id="$(json 'd["id"]')"
  fi

  for file in ${files[@]+"${files[@]}"}; do
    # If one with that name already exists (existing release), it is replaced.
    github_ok "read the release" GET "/repos/$repo/releases/$id"
    asset_id="$(json "next((a['id'] for a in d['assets'] if a['name'] == '$(basename "$file")'), None)")"
    if [[ -n "$asset_id" ]]; then
      github_ok "delete $(basename "$file")" DELETE "/repos/$repo/releases/assets/$asset_id"
    fi
    echo "  uploading $(basename "$file")"
    github_ok "upload $(basename "$file")" POST \
      "https://uploads.github.com/repos/$repo/releases/$id/assets?name=$(basename "$file")" \
      -H "Content-Type: application/octet-stream" --data-binary "@$file"
  done

  if [[ $existing == 0 ]]; then
    # "Latest" on GitHub is the CLI (the mobile libraries are not).
    latest=false
    if [[ "$component" == cli ]]; then latest=true; fi
    github_ok "publish the release" PATCH "/repos/$repo/releases/$id" \
      -d "$(json_object draft false make_latest "$latest")"
  fi
  say "Published $tag: https://github.com/$repo/releases/tag/$tag"
}

# With exit in every branch bash does not read this file again: it can be
# edited (or git pulled) while it builds.
case "${1:-}" in
  status) cmd_status; exit ;;
  version) shift; cmd_version "$@"; exit ;;
  build) shift; cmd_build "$@"; exit ;;
  publish) shift; cmd_publish "$@"; exit ;;
  deploy) shift; cmd_deploy "$@"; exit ;;
  download) shift; cmd_download "$@"; exit ;;
  *) awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$0"; exit 1 ;;
esac
