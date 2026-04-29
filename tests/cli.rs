use oldrar::rar13::{write_stored_archive, StoredEntry, WriterOptions};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/rar13")
        .join(name)
}

fn scratch(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!("oldrar-cli-{name}-{nonce}"));
    fs::create_dir_all(&path).unwrap();
    path
}

fn oldrar() -> Command {
    Command::new(env!("CARGO_BIN_EXE_oldrar"))
}

#[test]
fn info_lists_entries_and_comments() {
    let output = oldrar()
        .arg("info")
        .arg(fixture("COMMENT.RAR"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    let stdout = stdout(&output);
    assert!(stdout.contains("Rar13"));
    assert!(stdout.contains("HELLO.TXT"));
    assert!(stdout.contains("comment: This is the archive comment."));
}

#[test]
fn test_verifies_compressed_fixture() {
    let output = oldrar()
        .arg("test")
        .arg(fixture("README.RAR"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("OK README"));
}

#[test]
fn test_reassembles_compressed_multivolume_fixture() {
    let output = oldrar()
        .arg("test")
        .arg(fixture("CMULTIV.RAR"))
        .arg(fixture("CMULTIV.R00"))
        .arg(fixture("CMULTIV.R01"))
        .arg(fixture("CMULTIV.R02"))
        .arg(fixture("CMULTIV.R03"))
        .arg(fixture("CMULTIV.R04"))
        .arg(fixture("CMULTIV.R05"))
        .arg(fixture("CMULTIV.R06"))
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stdout(&output).contains("OK CMULTI.TXT"));
}

#[test]
fn extracts_stored_fixture() {
    let out_dir = scratch("extract");
    let output = oldrar()
        .arg("x")
        .arg(fixture("WITHDIR.RAR"))
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(
        fs::read(out_dir.join("SUBDIR").join("INNER.TXT")).unwrap(),
        b"Inside subdir.\r\n"
    );
}

#[test]
fn extracts_encrypted_compressed_fixture() {
    let out_dir = scratch("extract-encrypted");
    let output = oldrar()
        .args(["x", "--password", "password"])
        .arg(fixture("README_password=password.rar"))
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert_eq!(fs::read(out_dir.join("README")).unwrap().len(), 2016);
}

#[test]
fn rejects_wrong_password() {
    let output = oldrar()
        .args(["test", "--password", "wrong-password"])
        .arg(fixture("README_password=password.rar"))
        .output()
        .unwrap();
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("failed to test archive"));
    assert!(stderr.contains("invalid header") || stderr.contains("checksum mismatch"));
}

#[test]
fn rejects_unsafe_output_path() {
    let dir = scratch("unsafe-extract");
    let archive = dir.join("unsafe.rar");
    let out_dir = dir.join("out");
    let bytes = write_stored_archive(
        &[StoredEntry {
            name: b"../evil.txt",
            data: b"unsafe path fixture\n",
            file_time: 0,
            file_attr: 0x20,
            password: None,
            file_comment: None,
        }],
        WriterOptions::default(),
    )
    .unwrap();
    fs::write(&archive, bytes).unwrap();

    let extract = oldrar()
        .arg("x")
        .arg(&archive)
        .arg(&out_dir)
        .output()
        .unwrap();
    assert!(!extract.status.success());
    let stderr = stderr(&extract);
    assert!(stderr.contains("failed to write extracted entry"));
    assert!(stderr.contains("unsafe archive path"));
}

#[test]
fn creates_compressed_archive_that_can_be_tested() {
    let dir = scratch("create-compressed");
    let source = dir.join("tiny.txt");
    let archive = dir.join("created.rar");
    fs::write(&source, b"tiny payload over sixteen").unwrap();

    let create = oldrar()
        .arg("a")
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));

    let test = oldrar().arg("test").arg(&archive).output().unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK tiny.txt"));
}

#[test]
fn creates_stored_multivolume_archive_that_can_be_tested() {
    let dir = scratch("create-stored-multivolume");
    let source = dir.join("payload.bin");
    let archive = dir.join("split.rar");
    fs::write(&source, b"abcdefghijklmnopqrstuvwxyz0123456789").unwrap();

    let create = oldrar()
        .args(["a", "--store", "--volume-size", "10"])
        .arg(&archive)
        .arg(&source)
        .output()
        .unwrap();
    assert!(create.status.success(), "stderr: {}", stderr(&create));
    assert!(archive.exists());
    assert!(dir.join("split.r00").exists());
    assert!(dir.join("split.r01").exists());
    assert!(dir.join("split.r02").exists());

    let test = oldrar()
        .arg("test")
        .arg(&archive)
        .arg(dir.join("split.r00"))
        .arg(dir.join("split.r01"))
        .arg(dir.join("split.r02"))
        .output()
        .unwrap();
    assert!(test.status.success(), "stderr: {}", stderr(&test));
    assert!(stdout(&test).contains("OK payload.bin"));
}

#[test]
fn rejects_non_rar_input_to_info() {
    let dir = scratch("non-rar-info");
    let input = dir.join("plain.txt");
    fs::write(&input, b"not a rar archive").unwrap();

    let output = oldrar().arg("info").arg(&input).output().unwrap();
    assert!(!output.status.success());
    let stderr = stderr(&output);
    assert!(stderr.contains("failed to identify archive"));
    assert!(stderr.contains("unsupported archive signature"));
}

#[test]
fn prints_usage_for_help_command() {
    let output = oldrar().arg("--help").output().unwrap();
    assert!(output.status.success(), "stderr: {}", stderr(&output));
    assert!(stderr(&output).contains("oldrar info <archive>"));
}

fn stdout(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &std::process::Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}
