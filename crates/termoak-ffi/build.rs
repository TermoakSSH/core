fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    // Android: packed relative relocations (Android's APS2 format, read by
    // the loader since Android 6, API 23; the apps need 24+). Shrinks the
    // library's relocation table from 24 bytes per relocation to a few: about
    // 0.4 MB less per ABI.
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("android") {
        println!("cargo:rustc-cdylib-link-arg=-Wl,--pack-dyn-relocs=android");
    }
}
