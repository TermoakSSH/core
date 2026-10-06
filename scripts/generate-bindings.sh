#!/usr/bin/env bash
# Regenerates the Swift and Kotlin bindings from `termoak-ffi`.
#
#   bindings/swift/Sources/TermoakFFI/   TermoakFFI.swift + C header and modulemap
#   bindings/kotlin/src/main/kotlin/        com/termoak/ffi/termoak_ffi.kt
#
# The bindings do not depend on the architecture: they are generated from the
# library built for this machine (Linux or macOS). They are not formatted, so
# the output is the same on every machine (CI compares it).
# Usage: scripts/generate-bindings.sh
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

cargo build -p termoak-ffi --lib
target_dir="${CARGO_TARGET_DIR:-target}"
case "$(uname -s)" in
  Darwin) lib="$target_dir/debug/libtermoak_ffi.dylib" ;;
  *) lib="$target_dir/debug/libtermoak_ffi.so" ;;
esac

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
bindgen() {
  cargo run -q -p termoak-ffi --features bindgen --bin uniffi-bindgen -- \
    generate --no-format --library "$lib" --language "$1" --out-dir "$tmp/$1"
}
bindgen swift
bindgen kotlin

swift_dir="bindings/swift/Sources/TermoakFFI"
rm -rf "$swift_dir"
mkdir -p "$swift_dir"
cp "$tmp"/swift/* "$swift_dir/"

kotlin_dir="bindings/kotlin/src/main/kotlin"
rm -rf "$kotlin_dir/com/termoak/ffi"
mkdir -p "$kotlin_dir"
cp -R "$tmp/kotlin/." "$kotlin_dir/"

echo "Bindings regenerated:"
find "$swift_dir" "$kotlin_dir" -type f | sort
