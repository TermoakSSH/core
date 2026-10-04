# Image for building the Android app without Android Studio (used by
# scripts/release-local.sh: `build ffi` here and the Android app in
# TermoakSSH/mobile-android, which has this repository in core/).
#
# - JDK 17, Android SDK (platform 37, build-tools 37.0.0) and NDK 30.
# - Stable Rust with the Android targets and cargo-ndk, to build
#   termoak-ffi (libtermoak_ffi.so) for each ABI.
# - Gradle comes with the project itself (the app's gradlew).
FROM ubuntu:24.04

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      build-essential ca-certificates curl file git pkg-config unzip zip \
      openjdk-17-jdk-headless \
 && rm -rf /var/lib/apt/lists/*

ARG CMDLINE_TOOLS=16111833
ARG ANDROID_PLATFORM=37.0
ARG BUILD_TOOLS=37.0.0
ARG NDK=30.0.16248370
ENV ANDROID_HOME=/opt/android-sdk \
    ANDROID_SDK_ROOT=/opt/android-sdk \
    ANDROID_NDK_HOME=/opt/android-sdk/ndk/${NDK} \
    JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
RUN mkdir -p "$ANDROID_HOME/cmdline-tools" \
 && curl -fsSLo /tmp/tools.zip "https://dl.google.com/android/repository/commandlinetools-linux-${CMDLINE_TOOLS}_latest.zip" \
 && unzip -q /tmp/tools.zip -d "$ANDROID_HOME/cmdline-tools" \
 && mv "$ANDROID_HOME/cmdline-tools/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest" \
 && rm /tmp/tools.zip \
 && yes | "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --licenses >/dev/null \
 && "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --install \
      "platform-tools" "platforms;android-${ANDROID_PLATFORM}" "build-tools;${BUILD_TOOLS}" "ndk;${NDK}" >/dev/null \
 && ls -d "$ANDROID_HOME"/platforms/android-* "$ANDROID_HOME/build-tools/${BUILD_TOOLS}" "$ANDROID_HOME/ndk/${NDK}" \
 && chmod -R a+rX "$ANDROID_HOME"

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/opt/android-sdk/platform-tools:$PATH
RUN curl -fsSLo /tmp/rustup-init https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init \
 && chmod +x /tmp/rustup-init \
 && /tmp/rustup-init -y --no-modify-path --profile minimal --default-toolchain stable \
      --target aarch64-linux-android --target armv7-linux-androideabi --target x86_64-linux-android \
 && rm /tmp/rustup-init \
 && cargo install --locked cargo-ndk@4.1.2 \
 && rm -rf "$CARGO_HOME/registry" \
 && chmod -R a+rwX "$RUSTUP_HOME" "$CARGO_HOME"

ENV TERMOAK_ANDROID_BUILDER=1
