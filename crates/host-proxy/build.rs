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
