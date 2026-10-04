#!/usr/bin/env bash
# Builds termoak-ffi for Android with cargo-ndk and puts the libraries in
# bindings/kotlin/src/main/jniLibs/<abi>/libtermoak_ffi.so, next to the
# Kotlin bindings (bindings/kotlin/src/main/kotlin).
#
# Requirements: Android NDK (ANDROID_NDK_HOME or ANDROID_NDK_ROOT), rustup and
# cargo-ndk (`cargo install cargo-ndk`).
# NOT TESTED in CI (no NDK there): see docs/MOBILE.md.
#
# Usage: scripts/build-android.sh [release|debug]   (release by default)
# Variables: ANDROID_API (minimum API, 24 by default), ABIS (space-separated
# list, "arm64-v8a armeabi-v7a x86_64" by default).
set -euo pipefail

profile="${1:-release}"
case "$profile" in
  release) cargo_flags=(--release) ;;
  debug) cargo_flags=() ;;
  *) echo "unknown profile: $profile (use release or debug)" >&2; exit 1 ;;
esac

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

if [ -z "${ANDROID_NDK_HOME:-}" ] && [ -z "${ANDROID_NDK_ROOT:-}" ]; then
  echo "Set ANDROID_NDK_HOME to the NDK path (e.g. \$ANDROID_HOME/ndk/<version>)" >&2
  exit 1
fi
if ! command -v cargo-ndk >/dev/null 2>&1; then
  echo "cargo-ndk is missing: cargo install cargo-ndk" >&2
  exit 1
fi

api="${ANDROID_API:-24}"
read -r -a abis <<< "${ABIS:-arm64-v8a armeabi-v7a x86_64}"

rust_targets=()
ndk_args=()
for abi in "${abis[@]}"; do
  case "$abi" in
    arm64-v8a) rust_targets+=(aarch64-linux-android) ;;
    armeabi-v7a) rust_targets+=(armv7-linux-androideabi) ;;
    x86_64) rust_targets+=(x86_64-linux-android) ;;
    x86) rust_targets+=(i686-linux-android) ;;
    *) echo "unknown ABI: $abi" >&2; exit 1 ;;
  esac
  ndk_args+=(-t "$abi")
done
rustup target add "${rust_targets[@]}"

out="bindings/kotlin/src/main/jniLibs"
echo "==> cargo ndk (${abis[*]}, API $api, $profile)"
cargo ndk "${ndk_args[@]}" --platform "$api" -o "$out" \
  build -p termoak-ffi --lib ${cargo_flags[@]+"${cargo_flags[@]}"}

# Keep the Kotlin bindings up to date.
scripts/generate-bindings.sh

echo "Done:"
find "$out" -name '*.so' | sort
echo "Include bindings/kotlin as a Gradle module (see bindings/kotlin/build.gradle.kts)."
