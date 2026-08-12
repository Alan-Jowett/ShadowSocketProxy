// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Generates the tonic client bindings used by the host proxy.

/// Compiles the control protobuf with client bindings and requests reruns when
/// the protocol definition changes.
fn main() {
    reject_combined_tls_features();
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("protoc is available");
    std::env::set_var("PROTOC", protoc);
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&["../proto/control.proto"], &["../proto"])
        .expect("compile control protobuf");
    export_integration_binary_path();
    println!("cargo:rerun-if-changed=../proto/control.proto");
}

/// Rejects selecting both mutually exclusive TLS transports.
fn reject_combined_tls_features() {
    if std::env::var_os("CARGO_FEATURE_TLS_PSK").is_some()
        && std::env::var_os("CARGO_FEATURE_TLS_RUSTLS").is_some()
    {
        panic!("tls-psk and tls-rustls are mutually exclusive");
    }
}

/// Exports the host executable path under the underscore-normalized Cargo
/// variable used by the spawned rustls startup integration test.
fn export_integration_binary_path() {
    let out_dir = std::env::var_os("OUT_DIR").expect("Cargo must provide OUT_DIR");
    let target_dir = std::path::PathBuf::from(out_dir)
        .ancestors()
        .nth(3)
        .expect("Cargo build output must be nested below a target directory")
        .to_path_buf();
    let executable = if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        "shadow-socket-proxy-host.exe"
    } else {
        "shadow-socket-proxy-host"
    };
    println!(
        "cargo:rustc-env=CARGO_BIN_EXE_shadow_socket_proxy_host={}",
        target_dir.join(executable).display()
    );
}
