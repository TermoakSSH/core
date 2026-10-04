// Android (library) module with the Termoak bindings.
//
// Use it from your project with, in settings.gradle.kts:
//   include(":termoak")
//   project(":termoak").projectDir = file("core/bindings/kotlin")  // core as a git submodule
// and in the app: implementation(project(":termoak")).
// The root project sets the plugin versions.
//
// First, `scripts/build-android.sh` puts the native libraries in
// src/main/jniLibs. Used by the Android app, TermoakSSH/mobile-android (AGP 9, with built-in Kotlin: the
// kotlin-android plugin is not applied).
plugins {
    id("com.android.library")
}

android {
    namespace = "com.termoak.ffi"
    compileSdk = 37
    buildToolsVersion = "37.0.0"

    defaultConfig {
        minSdk = 24
        // JNA accesses the generated classes through reflection.
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17)
    }
}

dependencies {
    // UniFFI calls the native library through JNA (the AAR variant ships its .so files).
    implementation("net.java.dev.jna:jna:5.17.0@aar")
    // Rust `async` functions become `suspend`.
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.2")
    implementation("androidx.annotation:annotation:1.9.1")
}
