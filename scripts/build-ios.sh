#!/usr/bin/env bash
# Builds termoak-ffi for iOS and creates the Swift package xcframework
# (bindings/swift/termoak_ffiFFI.xcframework).
#
# Requirements: macOS with Xcode (xcodebuild, lipo) and rustup.
# NOT TESTED in CI (no Mac there): see docs/MOBILE.md.
#
# Usage: scripts/build-ios.sh [release|debug]   (release by default;
# release uses the size-optimized `mobile` Cargo profile)
set -euo pipefail

profile="${1:-release}"
case "$profile" in
  release) cargo_flags=(--profile mobile); out_dir=mobile ;;
  debug) cargo_flags=(); out_dir=debug ;;
  *) echo "unknown profile: $profile (use release or debug)" >&2; exit 1 ;;
esac

if [ "$(uname -s)" != "Darwin" ]; then
  echo "scripts/build-ios.sh requires macOS with Xcode" >&2
  exit 1
fi

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

# Device, Apple Silicon simulator and Intel simulator.
targets=(aarch64-apple-ios aarch64-apple-ios-sim x86_64-apple-ios)
rustup target add "${targets[@]}"
export IPHONEOS_DEPLOYMENT_TARGET="${IPHONEOS_DEPLOYMENT_TARGET:-15.0}"

for target in "${targets[@]}"; do
  echo "==> cargo build ($target, $profile)"
  cargo build -p termoak-ffi --lib ${cargo_flags[@]+"${cargo_flags[@]}"} --target "$target"
done

# Keep the Swift bindings up to date (generated from this machine's library).
scripts/generate-bindings.sh

lib="libtermoak_ffi.a"
work="$root/target/ios-xcframework"
rm -rf "$work"
mkdir -p "$work/simulator" "$work/headers/termoak_ffiFFI"

# A single simulator library with both architectures.
lipo -create \
  "target/aarch64-apple-ios-sim/$out_dir/$lib" \
  "target/x86_64-apple-ios/$out_dir/$lib" \
  -output "$work/simulator/$lib"

# C module header and modulemap. They go in a subdirectory named after the
# module so they don't clash with other xcframeworks' `module.modulemap`.
swift_dir="bindings/swift/Sources/TermoakFFI"
cp "$swift_dir/termoak_ffiFFI.h" "$work/headers/termoak_ffiFFI/"
cp "$swift_dir/termoak_ffiFFI.modulemap" "$work/headers/termoak_ffiFFI/module.modulemap"

xcframework="bindings/swift/termoak_ffiFFI.xcframework"
rm -rf "$xcframework"
xcodebuild -create-xcframework \
  -library "target/aarch64-apple-ios/$out_dir/$lib" -headers "$work/headers" \
  -library "$work/simulator/$lib" -headers "$work/headers" \
  -output "$xcframework"

echo "Done: $xcframework"
echo "Add bindings/swift as a local package in Xcode (File > Add Package Dependencies > Add Local...)."
