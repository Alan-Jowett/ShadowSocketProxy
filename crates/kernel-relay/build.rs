// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Generates control protobuf messages and, for native Windows builds, the
//! WSK bindings that are not provided by the WDK Rust crates.

fn main() {
    let protoc = protoc_bin_vendored::protoc_bin_path().expect("protoc is available");
    std::env::set_var("PROTOC", protoc);
    tonic_build::configure()
        .build_server(false)
        .build_client(false)
        .compile_protos(&["../proto/control.proto"], &["../proto"])
        .expect("compile control protobuf");
    println!("cargo:rerun-if-changed=../proto/control.proto");
    println!("cargo:rustc-check-cfg=cfg(ssp_wsk_windows)");
    println!("cargo:rustc-check-cfg=cfg(ssp_wsk_wdm)");
    println!("cargo:rustc-check-cfg=cfg(ssp_wdk_native)");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        println!("cargo:rustc-cfg=ssp_wsk_windows");
        println!("cargo:rustc-cfg=ssp_wsk_wdm");
        if std::env::var_os("CARGO_FEATURE_WDK_NATIVE").is_some() {
            configure_wdk_bindings();
            println!("cargo:rustc-cfg=ssp_wdk_native");
        }
    }
}

fn configure_wdk_bindings() {
    #[cfg(not(feature = "wdk-native"))]
    unreachable!("wdk-native build configuration was requested without the feature");

    #[cfg(feature = "wdk-native")]
    {
        use std::{
            env,
            path::{Path, PathBuf},
        };
        use wdk_build::BuilderExt;

        const WDK_VERSION: &str = "10.0.28000.2526";
        const SDK_PACKAGE: &str = "microsoft.windows.sdk.cpp";

        for variable in [
            "CARGO_CFG_TARGET_ARCH",
            "SSP_WSK_WDK_ROOT",
            "SSP_WSK_SDK_ROOT",
            "SSP_WSK_NUGET_ROOT",
            "NUGET_PACKAGES",
            "WDKContentRoot",
        ] {
            println!("cargo:rerun-if-env-changed={variable}");
        }
        println!("cargo:rerun-if-changed=include\\wsk_wrapper.h");

        let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
        let wdk_package = match arch.as_str() {
            "x86_64" => "microsoft.windows.wdk.x64",
            "aarch64" => "microsoft.windows.wdk.arm64",
            other => panic!("wdk-native supports only Windows x64 and ARM64, got {other}"),
        };

        let wdk_root = locate_root(
            "SSP_WSK_WDK_ROOT",
            "WDKContentRoot",
            wdk_package,
            WDK_VERSION,
            "wsk.h",
        );
        let sdk_root = locate_root("SSP_WSK_SDK_ROOT", "", SDK_PACKAGE, WDK_VERSION, "ws2def.h");
        let sdk_include = include_directory(&sdk_root, "ws2def.h");

        unsafe { env::set_var("WDKContentRoot", &wdk_root) };
        let config = wdk_build::Config::from_env_auto()
            .unwrap_or_else(|error| panic!("wdk-build could not configure WDM: {error}"));
        let wrapper = Path::new("include").join("wsk_wrapper.h");
        let wrapper = wrapper
            .to_str()
            .unwrap_or_else(|| panic!("WSK wrapper path is not valid UTF-8"));
        let bindings = bindgen::Builder::wdk_default(&config)
            .unwrap_or_else(|error| panic!("wdk-build could not configure bindgen: {error}"))
            .header(wrapper)
            .clang_arg(format!("--include-directory={}", sdk_include.display()))
            .clang_arg("-x")
            .clang_arg("c")
            .allowlist_type("WSK_.*")
            .allowlist_type("PWSK_.*")
            .allowlist_type("PFN_WSK_.*")
            .allowlist_type("sockaddr_in6")
            .allowlist_type("SOCKADDR_IN")
            .allowlist_type("SOCKADDR_IN6")
            .allowlist_type("IN_ADDR")
            .allowlist_type("IN6_ADDR")
            .allowlist_type("NPIID")
            .allowlist_var("AF_(INET|INET6)")
            .allowlist_var("IPPROTO_(TCP|UDP)")
            .allowlist_var("SOCK_(STREAM|DGRAM)")
            .allowlist_var("WSK_(FLAG|EVENT|SET_STATIC|INFINITE|NO_WAIT).*")
            .allowlist_var("NPI_WSK_INTERFACE_ID")
            .allowlist_function("Wsk(Register|CaptureProviderNPI|ReleaseProviderNPI|Deregister)")
            .generate_comments(false)
            .layout_tests(false)
            .generate()
            .unwrap_or_else(|error| panic!("bindgen failed for WSK headers: {error}"));
        let output = PathBuf::from(
            env::var_os("OUT_DIR").unwrap_or_else(|| panic!("OUT_DIR was not set by Cargo")),
        )
        .join("wsk_bindings.rs");
        bindings
            .write_to_file(&output)
            .unwrap_or_else(|error| panic!("could not write {}: {error}", output.display()));
        wdk_build::configure_wdk_binary_build()
            .unwrap_or_else(|error| panic!("wdk-build linker configuration failed: {error}"));
        println!("cargo:rustc-link-lib=netio");
    }
}

#[cfg(feature = "wdk-native")]
fn locate_root(
    primary: &str,
    secondary: &str,
    package: &str,
    version: &str,
    header: &str,
) -> std::path::PathBuf {
    use std::{env, path::PathBuf};
    let mut candidates = Vec::new();
    if let Some(root) = env::var_os(primary) {
        candidates.push(PathBuf::from(root));
    }
    if !secondary.is_empty() {
        if let Some(root) = env::var_os(secondary) {
            candidates.push(PathBuf::from(root));
        }
    }
    let nuget_root = env::var_os("SSP_WSK_NUGET_ROOT")
        .or_else(|| env::var_os("NUGET_PACKAGES"))
        .or_else(|| {
            env::var_os("USERPROFILE").map(|path| {
                PathBuf::from(path)
                    .join(".nuget\\packages")
                    .into_os_string()
            })
        });
    if let Some(root) = nuget_root {
        candidates.push(PathBuf::from(root).join(package).join(version).join("c"));
    }
    if let Some(root) = env::var_os("ProgramFiles") {
        candidates.push(PathBuf::from(root).join("Windows Kits\\10"));
    }
    candidates
        .into_iter()
        .map(normalize_root)
        .find(|root| include_directory(root, header).exists())
        .unwrap_or_else(|| {
            panic!("{header} was not found; install {package} {version} or set {primary}")
        })
}

#[cfg(feature = "wdk-native")]
fn normalize_root(root: std::path::PathBuf) -> std::path::PathBuf {
    if root.join("Include").is_dir() {
        root
    } else if root.join("c\\Include").is_dir() {
        root.join("c")
    } else {
        root
    }
}

#[cfg(feature = "wdk-native")]
fn include_directory(root: &std::path::Path, header: &str) -> std::path::PathBuf {
    let include = root.join("Include");
    let entries = std::fs::read_dir(&include)
        .unwrap_or_else(|error| panic!("could not inspect {}: {error}", include.display()));
    for entry in entries.flatten() {
        let versioned = entry.path();
        for subdir in ["shared", "km", "um"] {
            let candidate = versioned.join(subdir).join(header);
            if candidate.is_file() {
                return candidate
                    .parent()
                    .unwrap_or_else(|| panic!("invalid include path"))
                    .to_path_buf();
            }
        }
    }
    std::path::PathBuf::new()
}
