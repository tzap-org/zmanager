use std::process::Command;

#[test]
fn test_missing_argument_value_does_not_panic() {
    let output = Command::new(env!("CARGO_BIN_EXE_zm"))
        .arg("auth")
        .arg("login")
        .arg("--state-dir")
        // Missing the actual value for --state-dir
        .output()
        .expect("Failed to execute zm");

    // It should exit with a non-zero code (1), not a panic (e.g. 101)
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    
    // Check that it didn't panic (Rust panics usually contain "thread 'main' panicked")
    assert!(!stderr.contains("panicked"));
    assert!(stderr.contains("missing value for"));
}
