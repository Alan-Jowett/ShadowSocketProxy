// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Executable startup rejection coverage for the Windows rustls host proxy.

#![cfg(all(target_os = "windows", feature = "tls-rustls"))]

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
};

use rcgen::generate_simple_self_signed;

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct FixtureDirectory {
    path: PathBuf,
}

impl FixtureDirectory {
    fn new(name: &str) -> Self {
        let id = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target")
            .join(format!("rustls-startup-{name}-{}-{id}", std::process::id()));
        fs::create_dir_all(&path).expect("create rustls startup fixture directory");
        Self { path }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

fn base_arguments() -> Vec<String> {
    vec![
        "--bpf-elf".into(),
        "unused-bpf.elf".into(),
        "--interface".into(),
        "lo".into(),
    ]
}

fn run_host_proxy(arguments: &[String]) -> Output {
    let mut command = Command::new(
        std::env::var_os("CARGO_BIN_EXE_shadow-socket-proxy-host")
            .expect("Cargo must provide the host-proxy executable path"),
    );
    command
        .args(arguments)
        .env_remove("SSP_TLS_CERT_FILE")
        .env_remove("SSP_TLS_KEY_FILE")
        .env_remove("SSP_TLS_PEER_CERT_SHA256")
        .env_remove("SSP_TLS_PSK_IDENTITY")
        .env_remove("SSP_TLS_PSK_SECRET");
    command.output().expect("run host-proxy executable")
}

fn assert_startup_failure(arguments: &[String], expected_fragments: &[&str]) {
    let output = run_host_proxy(arguments);
    assert!(
        !output.status.success(),
        "host-proxy unexpectedly started: {output:?}"
    );
    let diagnostics = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        expected_fragments
            .iter()
            .any(|fragment| diagnostics.contains(fragment)),
        "diagnostics did not contain any of {expected_fragments:?}: {diagnostics}"
    );
}

fn write_valid_identity(directory: &FixtureDirectory) -> (PathBuf, PathBuf) {
    let generated = generate_simple_self_signed(vec!["server.invalid".to_owned()])
        .expect("generate test certificate");
    let certificate = directory.path("certificate.pem");
    let key = directory.path("key.pem");
    fs::write(&certificate, generated.cert.pem()).expect("write test certificate");
    fs::write(&key, generated.signing_key.serialize_pem()).expect("write test key");
    (certificate, key)
}

fn complete_tls_arguments(certificate: &Path, key: &Path, pin: &str) -> Vec<String> {
    let mut arguments = base_arguments();
    arguments.extend([
        "--tls-cert-file".into(),
        certificate.to_string_lossy().into_owned(),
        "--tls-key-file".into(),
        key.to_string_lossy().into_owned(),
        "--tls-peer-cert-sha256".into(),
        pin.into(),
    ]);
    arguments
}

#[test]
fn missing_certificate_file_is_rejected_at_startup() {
    let fixture = FixtureDirectory::new("missing-certificate");
    let certificate = fixture.path("missing-certificate.pem");
    let key = fixture.path("key.pem");
    let arguments = complete_tls_arguments(&certificate, &key, &"00".repeat(32));

    assert_startup_failure(&arguments, &["read TLS certificate file"]);
}

#[test]
fn malformed_certificate_file_is_rejected_at_startup() {
    let fixture = FixtureDirectory::new("malformed-certificate");
    let certificate = fixture.path("certificate.pem");
    let key = fixture.path("key.pem");
    fs::write(&certificate, b"not a certificate").expect("write malformed certificate");
    let arguments = complete_tls_arguments(&certificate, &key, &"00".repeat(32));

    assert_startup_failure(
        &arguments,
        &[
            "parse TLS certificate PEM",
            "TLS certificate file contains no certificates",
        ],
    );
}

#[test]
fn missing_key_file_is_rejected_at_startup() {
    let fixture = FixtureDirectory::new("missing-key");
    let (certificate, _) = write_valid_identity(&fixture);
    let key = fixture.path("missing-key.pem");
    let arguments = complete_tls_arguments(&certificate, &key, &"00".repeat(32));

    assert_startup_failure(&arguments, &["read TLS private key file"]);
}

#[test]
fn malformed_key_file_is_rejected_at_startup() {
    let fixture = FixtureDirectory::new("malformed-key");
    let (certificate, key) = write_valid_identity(&fixture);
    fs::write(&key, b"not a private key").expect("write malformed key");
    let arguments = complete_tls_arguments(&certificate, &key, &"00".repeat(32));

    assert_startup_failure(
        &arguments,
        &[
            "parse TLS private key PEM",
            "TLS private key file contains no supported private key",
        ],
    );
}

#[test]
fn missing_peer_pin_is_rejected_at_startup() {
    let fixture = FixtureDirectory::new("missing-peer-pin");
    let (certificate, key) = write_valid_identity(&fixture);
    let mut arguments = base_arguments();
    arguments.extend([
        "--tls-cert-file".into(),
        certificate.to_string_lossy().into_owned(),
        "--tls-key-file".into(),
        key.to_string_lossy().into_owned(),
    ]);

    assert_startup_failure(
        &arguments,
        &["--tls-cert-file, --tls-key-file, and --tls-peer-cert-sha256 are required"],
    );
}

#[test]
fn incomplete_tls_configuration_is_rejected_at_startup() {
    let fixture = FixtureDirectory::new("incomplete");
    let certificate = fixture.path("certificate.pem");
    let mut arguments = base_arguments();
    arguments.extend([
        "--tls-cert-file".into(),
        certificate.to_string_lossy().into_owned(),
    ]);

    assert_startup_failure(
        &arguments,
        &["--tls-cert-file, --tls-key-file, and --tls-peer-cert-sha256 are required"],
    );
}
