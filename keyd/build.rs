fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        println!("cargo:rerun-if-changed=native/TrustedApplication.c");
        cc::Build::new()
            .file("native/TrustedApplication.c")
            .flag("-Wno-deprecated-declarations")
            .compile("trusted_application");
    }
}
