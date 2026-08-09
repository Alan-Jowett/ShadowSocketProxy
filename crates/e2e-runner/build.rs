// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

/// Locates vendored `protoc`, generates client-only control bindings in
/// `OUT_DIR`, and makes Cargo rebuild when the control schema changes. The
/// build fails when vendored protoc cannot be located or protobuf compilation
/// rejects `../proto/control.proto`.
fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("protoc is available");
    std::env::set_var("PROTOC", protoc);
    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile_protos(&["../proto/control.proto"], &["../proto"])
        .expect("compile control protobuf");
    println!("cargo:rerun-if-changed=../proto/control.proto");
}
