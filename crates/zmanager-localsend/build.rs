use std::path::PathBuf;

fn main() {
    println!("cargo:rustc-check-cfg=cfg(localsend_rs_try_respond)");

    let manifest_dir = PathBuf::from(std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR"));
    let fork_manifest = manifest_dir.join("../../../localsend-rs/Cargo.toml");
    let fork_events = manifest_dir.join("../../../localsend-rs/src/server/events.rs");
    println!("cargo:rerun-if-changed={}", fork_manifest.display());
    println!("cargo:rerun-if-changed={}", fork_events.display());
    println!("cargo:rerun-if-env-changed=ZMANAGER_LOCALSEND_UPSTREAM_API");

    // Allows CI and maintainers to type-check the registry-compatible API
    // path even while the patched sibling is present.
    let force_upstream_api = std::env::var_os("ZMANAGER_LOCALSEND_UPSTREAM_API").is_some();
    let fork_checkout_present = fork_manifest.is_file();
    let fork_has_try_respond =
        std::fs::read_to_string(&fork_events).is_ok_and(|source| source.contains("pub fn try_respond(self, decision: TransferDecision)"));

    assert!(
        force_upstream_api || !fork_checkout_present || fork_has_try_respond,
        "the localsend-rs sibling checkout is missing the required try_respond patch"
    );
    if !force_upstream_api && fork_has_try_respond {
        println!("cargo:rustc-cfg=localsend_rs_try_respond");
    }
}
