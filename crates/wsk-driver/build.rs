// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

use std::env;
#[cfg(target_os = "windows")]
use std::{
    fs,
    path::{Path, PathBuf},
};
#[cfg(target_os = "windows")]
use wdk_build::BuilderExt;

fn main() {
    println!("cargo:rerun-if-changed=include\\wsk_wrapper.h");
    println!("cargo:rerun-if-changed=include\\ws2.h");
    for variable in [
        "CARGO_CFG_TARGET_OS",
        "CARGO_CFG_TARGET_ARCH",
        "CARGO_FEATURE_KERNEL",
        "SSP_WSK_WDK_ROOT",
        "SSP_WSK_SDK_ROOT",
        "SSP_WSK_NUGET_ROOT",
        "NUGET_PACKAGES",
        "WDKContentRoot",
    ] {
        println!("cargo:rerun-if-env-changed={variable}");
    }

    if env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows")
        && env::var_os("CARGO_FEATURE_KERNEL").is_some()
    {
        #[cfg(target_os = "windows")]
        if let Err(error) = configure_kernel_build() {
            panic!("WSK kernel build prerequisites are unavailable: {error}");
        }
    }
}

#[cfg(target_os = "windows")]
const WDK_VERSION: &str = "10.0.28000.2526";
#[cfg(target_os = "windows")]
const WDK_PACKAGE_X64: &str = "microsoft.windows.wdk.x64";
#[cfg(target_os = "windows")]
const WDK_PACKAGE_ARM64: &str = "microsoft.windows.wdk.arm64";
#[cfg(target_os = "windows")]
const SDK_PACKAGE: &str = "microsoft.windows.sdk.cpp";

#[cfg(target_os = "windows")]
fn configure_kernel_build() -> Result<(), String> {
    let arch = env::var("CARGO_CFG_TARGET_ARCH").unwrap_or_default();
    let package = match arch.as_str() {
        "x86_64" => WDK_PACKAGE_X64,
        "aarch64" => WDK_PACKAGE_ARM64,
        other => {
            return Err(format!(
                "only Windows x64 and ARM64 are supported, got target architecture {other}"
            ))
        }
    };

    let wdk_root = locate_wdk_root(package)?;
    let sdk_root = locate_sdk_root().or_else(|| {
        if has_header(&wdk_root, "ws2def.h") {
            Some(wdk_root.clone())
        } else {
            None
        }
    });
    let sdk_root = sdk_root.ok_or_else(|| {
        format!(
            "ws2def.h was not found; install Microsoft.Windows.SDK.CPP \
             {WDK_VERSION} or set SSP_WSK_SDK_ROOT"
        )
    })?;

    if !has_header(&wdk_root, "wsk.h") {
        return Err(format!(
            "wsk.h was not found below {}; install {package} {WDK_VERSION} \
             or set SSP_WSK_WDK_ROOT",
            wdk_root.display()
        ));
    }
    if !has_header(&sdk_root, "ws2def.h") {
        return Err(format!(
            "ws2def.h was not found below {}; install Microsoft.Windows.SDK.CPP \
             {WDK_VERSION} or set SSP_WSK_SDK_ROOT",
            sdk_root.display()
        ));
    }

    unsafe {
        env::set_var("WDKContentRoot", &wdk_root);
    }
    let config = wdk_build::Config::from_env_auto()
        .map_err(|error| format!("wdk-build could not configure WDM: {error}"))?;
    let wrapper = Path::new("include").join("wsk_wrapper.h");
    let sdk_include = include_directory(&sdk_root, "ws2def.h")?;
    let builder = bindgen::Builder::wdk_default(&config)
        .map_err(|error| format!("wdk-build could not configure bindgen: {error}"))?
        .header(
            wrapper
                .to_str()
                .ok_or_else(|| "WSK wrapper path is not valid UTF-8".to_string())?,
        )
        .clang_arg(format!("--include-directory={}", sdk_include.display()))
        .clang_arg("-x")
        .clang_arg("c")
        .allowlist_type("WSK_.*")
        .allowlist_type("PWSK_.*")
        .allowlist_type("PFN_WSK_.*")
        .allowlist_var("AF_(INET|INET6)")
        .allowlist_var("IPPROTO_(TCP|UDP)")
        .allowlist_var("SOCK_(STREAM|DGRAM)")
        .allowlist_var("WSK_(FLAG|EVENT|SET_STATIC|INFINITE|NO_WAIT).*")
        .allowlist_var("NPI_WSK_INTERFACE_ID")
        .allowlist_function("Wsk(Register|CaptureProviderNPI|ReleaseProviderNPI|Deregister)")
        .generate_comments(false)
        .layout_tests(false);
    let bindings = builder
        .generate()
        .map_err(|error| format!("bindgen failed for ws2.h/ws2def.h/wsk.h: {error}"))?;
    let output = PathBuf::from(
        env::var_os("OUT_DIR").ok_or_else(|| "OUT_DIR was not set by Cargo".to_string())?,
    )
    .join("wsk_bindings.rs");
    bindings
        .write_to_file(&output)
        .map_err(|error| format!("could not write {}: {error}", output.display()))?;

    wdk_build::configure_wdk_binary_build()
        .map_err(|error| format!("wdk-build linker configuration failed: {error}"))?;
    println!("cargo:rustc-link-lib=netio");
    Ok(())
}

#[cfg(target_os = "windows")]
fn locate_wdk_root(package: &str) -> Result<PathBuf, String> {
    let mut candidates = Vec::new();
    if let Some(root) = env::var_os("SSP_WSK_WDK_ROOT") {
        candidates.push(PathBuf::from(root));
    }
    if let Some(root) = env::var_os("WDKContentRoot") {
        candidates.push(PathBuf::from(root));
    }
    if let Some(root) = nuget_package_root(package) {
        candidates.push(root);
    }
    if let Some(program_files) = env::var_os("ProgramFiles") {
        candidates.push(PathBuf::from(program_files).join("Windows Kits\\10"));
    }

    candidates
        .into_iter()
        .map(normalize_content_root)
        .find(|root| has_header(root, "wsk.h"))
        .ok_or_else(|| {
            format!(
                "{package} {WDK_VERSION} was not found. Set SSP_WSK_WDK_ROOT to \
                 an extracted package c directory or install the package from NuGet"
            )
        })
}

#[cfg(target_os = "windows")]
fn locate_sdk_root() -> Option<PathBuf> {
    env::var_os("SSP_WSK_SDK_ROOT")
        .map(PathBuf::from)
        .into_iter()
        .chain(nuget_package_root(SDK_PACKAGE))
        .map(normalize_content_root)
        .find(|root| has_header(root, "ws2def.h"))
}

#[cfg(target_os = "windows")]
fn nuget_package_root(package: &str) -> Option<PathBuf> {
    let root = env::var_os("SSP_WSK_NUGET_ROOT")
        .or_else(|| env::var_os("NUGET_PACKAGES"))
        .or_else(|| {
            env::var_os("USERPROFILE")
                .map(|path| PathBuf::from(path).join(".nuget\\packages"))
                .map(|path| path.into_os_string())
        })?;
    Some(
        PathBuf::from(root)
            .join(package)
            .join(WDK_VERSION)
            .join("c"),
    )
}

#[cfg(target_os = "windows")]
fn normalize_content_root(root: PathBuf) -> PathBuf {
    if root.join("Include").is_dir() {
        root
    } else if root.join("c\\Include").is_dir() {
        root.join("c")
    } else {
        root
    }
}

#[cfg(target_os = "windows")]
fn has_header(root: &Path, header: &str) -> bool {
    include_directory(root, header).is_ok()
}

#[cfg(target_os = "windows")]
fn include_directory(root: &Path, header: &str) -> Result<PathBuf, String> {
    let include = root.join("Include");
    let entries = fs::read_dir(&include)
        .map_err(|error| format!("could not inspect {}: {error}", include.display()))?;
    for entry in entries.flatten() {
        let versioned = entry.path();
        if versioned.is_dir()
            && (versioned.join("shared").join(header).is_file()
                || versioned.join("km").join(header).is_file()
                || versioned.join("um").join(header).is_file())
        {
            return Ok(versioned.join("shared"));
        }
    }
    Err(format!(
        "{header} was not found below {}",
        include.display()
    ))
}
