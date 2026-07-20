#![cfg(target_os = "linux")]

use std::process::Command;

#[test]
fn proc_backend_runs_without_a_tty() {
    let output = Command::new(env!("CARGO_BIN_EXE_flowtop"))
        .args([
            "--backend",
            "proc",
            "--no-ui",
            "--interval",
            "100ms",
            "--duration",
            "150ms",
        ])
        .output()
        .expect("run flowtop");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert!(lines.len() >= 2);
    for line in lines {
        let value: serde_json::Value = serde_json::from_str(line).expect("valid JSONL snapshot");
        assert_eq!(value["record_type"], "snapshot");
        assert!(value["tcp"]["accepted_established"].is_null());
    }
}
