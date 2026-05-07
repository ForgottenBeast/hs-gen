use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;

fn hs_gen_bin() -> std::path::PathBuf {
    let mut path = std::env::current_exe().unwrap();
    // Go up from deps/ to debug/
    path.pop();
    if path.ends_with("deps") {
        path.pop();
    }
    path.join("hs-gen")
}

fn build_bin() {
    let status = Command::new("cargo")
        .args(["build", "--bin", "hs-gen"])
        .status()
        .expect("failed to run cargo build");
    assert!(status.success(), "cargo build failed");
}

#[test]
fn test_one_shot_tor_stdout() {
    build_bin();
    let bin = hs_gen_bin();
    let mut child = Command::new(&bin)
        .args(["--tor", "--validity", "3600"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn hs-gen");

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"testpassword")
        .unwrap();
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("failed to wait");
    assert!(output.status.success(), "exit code: {}", output.status);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(".onion"),
        "output should contain .onion: {stdout}"
    );
}

#[test]
fn test_one_shot_i2p_stdout() {
    build_bin();
    let bin = hs_gen_bin();
    let mut child = Command::new(&bin)
        .args(["--i2p", "--validity", "3600"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn hs-gen");

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"testpassword")
        .unwrap();
    drop(child.stdin.take());

    let output = child.wait_with_output().expect("failed to wait");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(".b32.i2p"),
        "output should contain .b32.i2p: {stdout}"
    );
}

#[test]
fn test_determinism_across_invocations() {
    build_bin();
    let bin = hs_gen_bin();

    let run = || {
        let mut child = Command::new(&bin)
            .args(["--tor", "--validity", "86400"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"same_password")
            .unwrap();
        drop(child.stdin.take());
        let out = child.wait_with_output().unwrap();
        String::from_utf8_lossy(&out.stdout).to_string()
    };

    // Same password + same epoch (86400s = 24h, won't change mid-test) → same output
    let out1 = run();
    let out2 = run();
    assert_eq!(out1, out2, "determinism failed: outputs differ");
}

#[test]
fn test_output_dir_no_overwrite() {
    build_bin();
    let bin = hs_gen_bin();
    let dir = TempDir::new().unwrap();

    let mut child = Command::new(&bin)
        .args([
            "--tor",
            "--i2p",
            "--validity",
            "3600",
            "--output-dir",
            dir.path().to_str().unwrap(),
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"testpassword")
        .unwrap();
    drop(child.stdin.take());
    let status = child.wait_with_output().unwrap().status;
    assert!(status.success());

    // Should have created <epoch>/tor/ and <epoch>/i2p/
    let entries: Vec<_> = std::fs::read_dir(dir.path()).unwrap().collect();
    assert_eq!(entries.len(), 1, "expected exactly one epoch dir");

    let epoch_dir = entries[0].as_ref().unwrap().path();
    assert!(epoch_dir.join("tor/hs_ed25519_secret_key").exists());
    assert!(epoch_dir.join("tor/hostname").exists());
    assert!(epoch_dir.join("i2p/destination.dat").exists());
    assert!(epoch_dir.join("i2p/destination.b32.i2p").exists());
}

#[test]
fn test_output_dir_overwrite() {
    build_bin();
    let bin = hs_gen_bin();
    let dir = TempDir::new().unwrap();

    for _ in 0..2 {
        let mut child = Command::new(&bin)
            .args([
                "--tor",
                "--validity",
                "3600",
                "--output-dir",
                dir.path().to_str().unwrap(),
                "--overwrite",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(b"testpassword")
            .unwrap();
        drop(child.stdin.take());
        child.wait_with_output().unwrap();
    }

    // Should have tor/ directly in output dir, no epoch subdir
    assert!(dir.path().join("tor/hs_ed25519_secret_key").exists());
    // No epoch subdirs
    let entries: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .filter(|e| e.file_name() != "tor" && e.file_name() != "i2p")
        .collect();
    assert!(
        entries.is_empty(),
        "unexpected entries in output dir: {entries:?}"
    );
}

#[test]
fn test_default_generates_both() {
    // With no --tor/--i2p flags, both networks should be generated
    build_bin();
    let bin = hs_gen_bin();
    let mut child = Command::new(&bin)
        .args(["--validity", "3600"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"testpassword")
        .unwrap();
    drop(child.stdin.take());

    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "should succeed with no flags");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains(".onion"), "output should contain .onion: {stdout}");
    assert!(stdout.contains(".b32.i2p"), "output should contain .b32.i2p: {stdout}");
}

#[test]
fn test_validation_validity_too_small() {
    build_bin();
    let bin = hs_gen_bin();
    let status = Command::new(&bin)
        .args(["--tor", "--validity", "30"])
        .stdin(Stdio::piped())
        .spawn()
        .unwrap()
        .wait()
        .unwrap();
    assert!(!status.success());
}

#[test]
fn test_daemon_initial_rotation_and_shutdown() {
    build_bin();
    let bin = hs_gen_bin();
    let dir = TempDir::new().unwrap();

    let mut child = Command::new(&bin)
        .args([
            "--tor",
            "--validity",
            "120",
            "--output-dir",
            dir.path().to_str().unwrap(),
            "--daemon",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to spawn daemon");

    // Send password as first line, then shutdown command
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(b"testpassword\n").unwrap();
        // Give daemon time to start and emit started + rotated
        std::thread::sleep(Duration::from_millis(500));
        stdin.write_all(b"{\"cmd\":\"shutdown\"}\n").unwrap();
        stdin.flush().unwrap();
    }

    let output = child.wait_with_output().expect("daemon did not exit");
    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        stdout.contains("\"event\":\"started\""),
        "missing started event: {stdout}"
    );
    assert!(
        stdout.contains("\"event\":\"rotated\""),
        "missing rotated event: {stdout}"
    );
    assert!(
        stdout.contains("\"event\":\"shutdown\""),
        "missing shutdown event: {stdout}"
    );
    assert!(
        stdout.contains(".onion"),
        "rotated event should include onion address: {stdout}"
    );

    // Verify all event lines are < 4096 bytes
    for line in stdout.lines() {
        assert!(
            line.len() < 4096,
            "event line too long ({} bytes): {line}",
            line.len()
        );
    }
}

#[test]
fn test_daemon_set_validity() {
    build_bin();
    let bin = hs_gen_bin();
    let dir = TempDir::new().unwrap();

    let mut child = Command::new(&bin)
        .args([
            "--tor",
            "--validity",
            "120",
            "--output-dir",
            dir.path().to_str().unwrap(),
            "--daemon",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(b"testpassword\n").unwrap();
        std::thread::sleep(Duration::from_millis(300));
        stdin
            .write_all(b"{\"cmd\":\"set_validity\",\"seconds\":300}\n")
            .unwrap();
        std::thread::sleep(Duration::from_millis(200));
        stdin.write_all(b"{\"cmd\":\"shutdown\"}\n").unwrap();
        stdin.flush().unwrap();
    }

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"event\":\"validity_changed\""),
        "missing validity_changed: {stdout}"
    );
    assert!(
        stdout.contains("\"new_validity\":300"),
        "wrong new_validity: {stdout}"
    );
}

#[test]
fn test_daemon_stdin_eof_triggers_shutdown() {
    build_bin();
    let bin = hs_gen_bin();
    let dir = TempDir::new().unwrap();

    let mut child = Command::new(&bin)
        .args([
            "--tor",
            "--validity",
            "120",
            "--output-dir",
            dir.path().to_str().unwrap(),
            "--daemon",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();

    // Send password, wait for startup, then close stdin (EOF)
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(b"testpassword\n").unwrap();
        std::thread::sleep(Duration::from_millis(400));
    }
    drop(child.stdin.take()); // close stdin → EOF

    let output = child.wait_with_output().unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("\"event\":\"shutdown\""),
        "missing shutdown on EOF: {stdout}"
    );
    assert!(output.status.success());
}
