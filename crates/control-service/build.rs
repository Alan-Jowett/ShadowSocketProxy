// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

use std::{
    env,
    io::Write,
    process::{Command, Stdio},
};

fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("protoc is available");
    std::env::set_var("PROTOC", protoc);
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["../proto/control.proto"], &["../proto"])
        .expect("compile control protobuf");
    println!("cargo:rerun-if-changed=../proto/control.proto");
    println!("cargo:rustc-check-cfg=cfg(ssp_openssl_no_psk)");
    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        detect_openssl_psk();
    }
}

fn detect_openssl_psk() {
    let compiler = env::var("CC").unwrap_or_else(|_| "cc".into());
    let mut command = Command::new(compiler);
    if let Ok(output) = Command::new("pkg-config")
        .args(["--cflags", "openssl"])
        .output()
    {
        if output.status.success() {
            command.args(String::from_utf8_lossy(&output.stdout).split_whitespace());
        }
    }
    command.args(["-dM", "-E", "-x", "c", "-include", "openssl/ssl.h", "-"]);
    let Ok(mut child) = command.stdin(Stdio::piped()).stdout(Stdio::piped()).spawn() else {
        return;
    };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(b"\n");
    }
    let Ok(output) = child.wait_with_output() else {
        return;
    };
    if output.status.success()
        && output
            .stdout
            .windows(b"OPENSSL_NO_PSK".len())
            .any(|window| window == b"OPENSSL_NO_PSK")
    {
        println!("cargo:rustc-cfg=ssp_openssl_no_psk");
    }
}
