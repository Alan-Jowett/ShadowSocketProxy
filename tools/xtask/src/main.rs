// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

use serde::Serialize;
use sha2::{Digest, Sha256};
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;
#[cfg(windows)]
use std::os::windows::process::CommandExt;
use std::{
    collections::BTreeSet,
    env,
    ffi::OsString,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    MoveFileExW, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
};

const WDK_VERSION: &str = "10.0.28000.2526";
const LLVM_MIN_MAJOR: u32 = 18;

#[derive(Debug, Clone, PartialEq, Eq)]
struct BuildPlan {
    release: bool,
    wsl: bool,
    tls: Option<TlsMode>,
    kernel_relay: bool,
    test_signing: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum TlsMode {
    Psk,
    Rustls,
}

#[derive(Debug, Clone, Serialize)]
struct Artifact {
    name: String,
    path: String,
    sha256: String,
}

#[derive(Debug, Serialize)]
struct Manifest {
    profile: String,
    features: Vec<String>,
    target_triples: Vec<String>,
    artifacts: Vec<Artifact>,
    signing: String,
    certificate_thumbprint: Option<String>,
    reboot_required: bool,
    resolved_versions: Vec<String>,
    tool_paths: Vec<String>,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("shadow-socket-proxy build failed: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let plan = parse_args(env::args_os().skip(1))?;
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .ok_or_else(|| "unable to locate repository root".to_owned())?
        .to_path_buf();
    let profile = if plan.release { "release" } else { "debug" };
    let run_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| format!("clock error: {error}"))?
        .as_millis();
    let output_root = repo.join("target").join("ssp-build").join(profile);
    let staging = output_root.join(format!(".staging-{run_id}"));
    fs::create_dir_all(&staging).map_err(|error| format!("create staging directory: {error}"))?;

    let result = build(&repo, &staging, profile, &plan);
    match result {
        Ok((artifacts, signing, thumbprint, reboot_required, versions, tools)) => {
            fs::create_dir_all(&output_root)
                .map_err(|error| format!("create output directory: {error}"))?;
            let mut artifacts = artifacts;
            for artifact in &mut artifacts {
                let destination = output_root.join(&artifact.name);
                fs::copy(&artifact.path, &destination)
                    .map_err(|error| format!("publish {}: {error}", artifact.name))?;
                artifact.path = destination.to_string_lossy().into_owned();
            }
            let manifest = Manifest {
                profile: profile.to_owned(),
                features: plan.feature_names(),
                target_triples: target_triples(&plan),
                artifacts,
                signing,
                certificate_thumbprint: thumbprint,
                reboot_required,
                resolved_versions: versions,
                tool_paths: tools,
            };
            let manifest_path = staging.join("manifest.json");
            let json = serde_json::to_vec_pretty(&manifest)
                .map_err(|error| format!("serialize manifest: {error}"))?;
            fs::write(&manifest_path, json).map_err(|error| format!("write manifest: {error}"))?;
            let published = output_root.join("manifest.json");
            replace_file(&manifest_path, &published)?;
            fs::remove_dir_all(&staging)
                .map_err(|error| format!("remove staging directory: {error}"))?;
            println!("published {}", published.display());
            Ok(())
        }
        Err(error) => {
            let _ = fs::remove_dir_all(&staging);
            Err(error)
        }
    }
}

fn parse_args<I>(args: I) -> Result<BuildPlan, String>
where
    I: IntoIterator<Item = OsString>,
{
    let args = args
        .into_iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    if args.first().map(String::as_str) != Some("build") {
        return Err("usage: cargo xtask build [--release] [--features <feature> ...]".to_owned());
    }

    let mut release = false;
    let mut features = BTreeSet::new();
    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--release" => release = true,
            "--features" => {
                index += 1;
                if index == args.len() {
                    return Err("--features requires at least one value".to_owned());
                }
                while index < args.len() && !args[index].starts_with('-') {
                    for feature in
                        args[index].split(|character| matches!(character, ',' | '+' | ' ' | ';'))
                    {
                        if !feature.is_empty() {
                            features.insert(feature.replace('_', "-"));
                        }
                    }
                    index += 1;
                }
                index -= 1;
            }
            value if value.starts_with("--features=") => {
                for feature in value["--features=".len()..]
                    .split(|character| matches!(character, ',' | '+' | ' ' | ';'))
                {
                    if !feature.is_empty() {
                        features.insert(feature.replace('_', "-"));
                    }
                }
            }
            value => return Err(format!("unknown argument `{value}`")),
        }
        index += 1;
    }

    let known = [
        "wsl",
        "tls-psk",
        "tls-rustls",
        "kernel-relay",
        "test-signing",
    ];
    if let Some(unknown) = features
        .iter()
        .find(|feature| !known.contains(&feature.as_str()))
    {
        return Err(format!("unknown feature `{unknown}`"));
    }
    if features.contains("tls-psk") && features.contains("tls-rustls") {
        return Err("tls-psk and tls-rustls are mutually exclusive".to_owned());
    }
    if features.contains("test-signing") && !features.contains("kernel-relay") {
        return Err("test-signing requires kernel-relay".to_owned());
    }

    Ok(BuildPlan {
        release,
        wsl: features.contains("wsl"),
        tls: if features.contains("tls-psk") {
            Some(TlsMode::Psk)
        } else if features.contains("tls-rustls") {
            Some(TlsMode::Rustls)
        } else {
            None
        },
        kernel_relay: features.contains("kernel-relay"),
        test_signing: features.contains("test-signing"),
    })
}

impl BuildPlan {
    fn feature_names(&self) -> Vec<String> {
        let mut features = Vec::new();
        if self.wsl {
            features.push("wsl".to_owned());
        }
        if let Some(tls) = self.tls {
            features.push(
                match tls {
                    TlsMode::Psk => "tls-psk",
                    TlsMode::Rustls => "tls-rustls",
                }
                .to_owned(),
            );
        }
        if self.kernel_relay {
            features.push("kernel-relay".to_owned());
        }
        if self.test_signing {
            features.push("test-signing".to_owned());
        }
        features
    }
}

fn target_triples(plan: &BuildPlan) -> Vec<String> {
    let mut targets = vec!["x86_64-pc-windows-msvc".to_owned()];
    if plan.wsl {
        targets.push("x86_64-unknown-linux-gnu".to_owned());
    }
    targets
}

type BuildResult = (
    Vec<Artifact>,
    String,
    Option<String>,
    bool,
    Vec<String>,
    Vec<String>,
);

fn build(
    repo: &Path,
    staging: &Path,
    profile: &str,
    plan: &BuildPlan,
) -> Result<BuildResult, String> {
    preflight(plan)?;
    let mut versions = Vec::new();
    let mut tools = Vec::new();
    let mut artifacts = Vec::new();

    if plan.wsl {
        let distro = env::var("SSP_WSL_DISTRO").unwrap_or_else(|_| "Ubuntu".to_owned());
        run_wsl_build(repo, profile, &distro, plan)?;
        collect_if_exists(
            staging,
            "shadow-socket-proxy.bpf.o",
            &repo
                .join("crates")
                .join("bpf")
                .join("shadow-socket-proxy.bpf.o"),
            &mut artifacts,
        )?;
        collect_if_exists(
            staging,
            "ssp-bpf-fixture-runner",
            &repo
                .join("crates")
                .join("bpf")
                .join("ssp-bpf-fixture-runner"),
            &mut artifacts,
        )?;
        let linux_binary = repo
            .join("target")
            .join("x86_64-unknown-linux-gnu")
            .join(profile)
            .join("shadow-socket-proxy-control");
        collect_if_exists(
            staging,
            "shadow-socket-proxy-control",
            &linux_binary,
            &mut artifacts,
        )?;
    }
    if plan.tls == Some(TlsMode::Psk) {
        versions.push(format!("openssl={}", detected_openssl_version()));
    }

    let host_features = tls_feature(plan.tls);
    cargo_build(
        repo,
        profile,
        "shadow-socket-proxy-host",
        host_features.as_deref(),
        None,
    )?;
    let host_binary = repo
        .join("target")
        .join(profile)
        .join("shadow-socket-proxy-host.exe");
    collect_if_exists(
        staging,
        "shadow-socket-proxy-host.exe",
        &host_binary,
        &mut artifacts,
    )?;

    if plan.kernel_relay {
        versions.push(format!(
            "llvm={}",
            detected_version("clang", &["--version"])
        ));
        let roots = discover_wdk()?;
        versions.extend(roots.versions);
        tools.extend(roots.tools);
        let mut command = Command::new("cargo");
        command.current_dir(repo).args([
            "build",
            "--locked",
            "-p",
            "shadow-socket-proxy-kernel-relay",
        ]);
        if plan.release {
            command.arg("--release");
        }
        command.args([
            "--target",
            "x86_64-pc-windows-msvc",
            "--no-default-features",
            "--features",
            "wdk-native",
        ]);
        for (key, value) in discover_msvc_environment()? {
            command.env(key, value);
        }
        for (key, value) in roots.environment {
            command.env(key, value);
        }
        run_command(&mut command, "native kernel driver build")?;
        let driver = repo
            .join("target")
            .join("x86_64-pc-windows-msvc")
            .join(profile)
            .join("shadow_socket_proxy_kernel_relay.dll");
        let driver_name = if cfg!(target_os = "windows") {
            "shadow_socket_proxy_kernel_relay.dll"
        } else {
            "shadow_socket_proxy_kernel_relay"
        };
        collect_if_exists(staging, driver_name, &driver, &mut artifacts)?;
    }

    let (signing, thumbprint, reboot_required) =
        sign_driver(repo, staging, plan, &mut artifacts, &mut tools)?;
    Ok((
        artifacts,
        signing,
        thumbprint,
        reboot_required,
        versions,
        tools,
    ))
}

fn preflight(plan: &BuildPlan) -> Result<(), String> {
    require_command("cargo", "Rust/Cargo")?;
    if plan.tls == Some(TlsMode::Psk) {
        ensure_openssl()?;
    }
    if plan.wsl {
        require_command("wsl.exe", "WSL")?;
    }
    if plan.kernel_relay {
        require_command("cargo", "Rust/Cargo")?;
        powershell_executable()?;
        ensure_llvm()?;
        ensure_wdk_packages()?;
    }

    fn ensure_wdk_packages() -> Result<(), String> {
        let package_root = env::var("SSP_WSK_NUGET_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(|_| {
                env::var("USERPROFILE")
                    .map(|home| PathBuf::from(home).join(".nuget").join("packages"))
                    .unwrap_or_else(|_| PathBuf::from("."))
            });
        for package in [
            "microsoft.windows.wdk.x64",
            "microsoft.windows.wdk.arm64",
            "microsoft.windows.sdk.cpp",
        ] {
            let destination = package_root.join(package).join(WDK_VERSION);
            if destination.join("c").exists() {
                continue;
            }
            fs::create_dir_all(&destination)
                .map_err(|error| format!("create NuGet destination: {error}"))?;
            let archive = destination.join(format!("{package}.{WDK_VERSION}.nupkg"));
            let url = format!(
                "https://api.nuget.org/v3-flatcontainer/{package}/{WDK_VERSION}/{package}.{WDK_VERSION}.nupkg"
            );
            let mut download = Command::new(powershell_executable()?);
            download.args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                &format!(
                    "Invoke-WebRequest -UseBasicParsing -Uri '{}' -OutFile '{}'; Expand-Archive -Force '{}' '{}'",
                    url,
                    archive.display(),
                    archive.display(),
                    destination.display()
                ),
            ]);
            run_command(&mut download, &format!("download NuGet package {package}"))?;
            let _ = fs::remove_file(archive);
        }
        Ok(())
    }

    Ok(())
}

fn powershell_executable() -> Result<OsString, String> {
    for candidate in ["powershell.exe", "pwsh"] {
        let available = Command::new(candidate)
            .arg("-NoProfile")
            .arg("-Command")
            .arg("$PSVersionTable.PSVersion.ToString()")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        if available {
            return Ok(OsString::from(candidate));
        }
    }
    Err("PowerShell prerequisite was not found; install powershell.exe or pwsh".to_owned())
}

fn discover_msvc_environment() -> Result<Vec<(String, String)>, String> {
    let vcvars = locate_vcvars64()?;
    let command_line = format!("call \"{}\" >nul && set", vcvars.display());
    let mut command = Command::new("cmd.exe");
    command.args(["/d", "/c"]);
    #[cfg(windows)]
    command.raw_arg(&command_line);
    #[cfg(not(windows))]
    command.arg(&command_line);
    let output = command
        .output()
        .map_err(|error| format!("start Visual Studio environment: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "Visual Studio environment initialization failed with {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let mut environment = Vec::new();
    for line in String::from_utf8_lossy(&output.stdout).lines() {
        if let Some((key, value)) = line.split_once('=') {
            environment.push((key.to_owned(), value.to_owned()));
        }
    }
    let has_toolchain = ["PATH", "INCLUDE", "LIB"].iter().all(|key| {
        environment
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case(key))
    });
    if !has_toolchain {
        let keys = environment
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(
            format!(
                "Visual Studio environment did not expose PATH, INCLUDE, and LIB; observed environment keys: {keys}; install the MSVC C++ toolset"
            ),
        );
    }
    Ok(environment)
}

fn locate_vcvars64() -> Result<PathBuf, String> {
    if let Ok(path) = env::var("SSP_VCVARS64_BAT") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
    }
    let vswhere_candidates = [
        PathBuf::from("vswhere.exe"),
        PathBuf::from(r"C:\Program Files (x86)\Microsoft Visual Studio\Installer\vswhere.exe"),
        PathBuf::from(r"C:\Program Files\Microsoft Visual Studio\Installer\vswhere.exe"),
    ];
    for vswhere in vswhere_candidates {
        if let Ok(output) = Command::new(&vswhere)
            .args([
                "-latest",
                "-products",
                "*",
                "-requires",
                "Microsoft.VisualStudio.Component.VC.Tools.x86.x64",
                "-property",
                "installationPath",
            ])
            .output()
        {
            if let Some(root) = String::from_utf8_lossy(&output.stdout)
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty())
            {
                let path = PathBuf::from(root)
                    .join("VC")
                    .join("Auxiliary")
                    .join("Build")
                    .join("vcvars64.bat");
                if path.exists() {
                    return Ok(path);
                }
            }
        }
    }
    let roots = [
        env::var_os("ProgramFiles(x86)").map(PathBuf::from),
        env::var_os("ProgramFiles").map(PathBuf::from),
    ];
    for root in roots.into_iter().flatten() {
        for year in ["18", "2022", "2019"] {
            for edition in ["BuildTools", "Community", "Professional", "Enterprise"] {
                let path = root
                    .join("Microsoft Visual Studio")
                    .join(year)
                    .join(edition)
                    .join("VC")
                    .join("Auxiliary")
                    .join("Build")
                    .join("vcvars64.bat");
                if path.exists() {
                    return Ok(path);
                }
            }
        }
    }
    Err(
        "MSVC environment not found; install the Visual Studio C++ toolset or set SSP_VCVARS64_BAT"
            .to_owned(),
    )
}

fn require_command(command: &str, label: &str) -> Result<(), String> {
    let status = Command::new(command)
        .arg("--version")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|_| format!("{label} prerequisite `{command}` was not found"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{label} prerequisite `{command}` is unavailable"))
    }
}

fn ensure_llvm() -> Result<(), String> {
    let candidates = [
        PathBuf::from("clang"),
        PathBuf::from(r"C:\Program Files\LLVM\bin\clang.exe"),
    ];
    for candidate in candidates {
        let version = Command::new(&candidate)
            .arg("--version")
            .output()
            .ok()
            .and_then(|output| String::from_utf8(output.stdout).ok())
            .and_then(|text| {
                text.split_whitespace().find_map(|word| {
                    word.split_once('.')
                        .and_then(|(major, _)| major.parse::<u32>().ok())
                })
            });
        if version.is_some_and(|major| major >= LLVM_MIN_MAJOR) {
            if env::var_os("LIBCLANG_PATH").is_none() {
                let candidate = PathBuf::from(r"C:\Program Files\LLVM\bin");
                if candidate.join("libclang.dll").exists() {
                    env::set_var("LIBCLANG_PATH", candidate);
                }
            }
            return Ok(());
        }
    }
    install_winget("LLVM.LLVM", env::var("SSP_LLVM_PACKAGE_VERSION").ok())?;
    let candidate = PathBuf::from(r"C:\Program Files\LLVM\bin");
    if candidate.join("libclang.dll").exists() {
        env::set_var("LIBCLANG_PATH", candidate);
    }
    Ok(())
}

fn ensure_openssl() -> Result<(), String> {
    if let Some(root) = env::var_os("OPENSSL_DIR").map(PathBuf::from) {
        return set_openssl_environment(&root);
    }
    let candidates = [
        PathBuf::from(r"C:\Program Files\OpenSSL-Win64"),
        PathBuf::from(r"C:\Program Files\OpenSSL"),
    ];
    if candidates.iter().any(|root| valid_openssl_root(root)) {
        let root = candidates
            .iter()
            .find(|root| valid_openssl_root(root))
            .expect("candidate checked above");
        return set_openssl_environment(root);
    }
    install_winget(
        "ShiningLight.OpenSSL.Dev",
        env::var("SSP_OPENSSL_PACKAGE_VERSION").ok(),
    )?;
    let root = candidates
        .iter()
        .find(|root| valid_openssl_root(root))
        .ok_or_else(|| {
            "OpenSSL installation completed but its headers or executable were not found".to_owned()
        })?;
    set_openssl_environment(root)
}

fn valid_openssl_root(root: &Path) -> bool {
    root.join("include").join("openssl").exists() && root.join("bin").join("openssl.exe").exists()
}

fn set_openssl_environment(root: &Path) -> Result<(), String> {
    let include = root.join("include");
    let lib = [
        root.join("lib").join("VC").join("x64").join("MD"),
        root.join("lib"),
    ]
    .into_iter()
    .find(|path| path.exists())
    .ok_or_else(|| {
        format!(
            "OpenSSL library directory was not found below {}",
            root.display()
        )
    })?;
    if !include.join("openssl").exists() || !root.join("bin").join("openssl.exe").exists() {
        return Err(format!(
            "OpenSSL headers or executable were not found below {}",
            root.display()
        ));
    }
    env::set_var("OPENSSL_DIR", root);
    env::set_var("OPENSSL_INCLUDE_DIR", include);
    env::set_var("OPENSSL_LIB_DIR", lib);
    Ok(())
}

fn install_winget(id: &str, version: Option<String>) -> Result<(), String> {
    require_command("winget", "winget")?;
    let mut command = Command::new("winget");
    command.args([
        "install",
        "--id",
        id,
        "--exact",
        "--scope",
        "machine",
        "--accept-source-agreements",
        "--accept-package-agreements",
    ]);
    if let Some(version) = version {
        command.args(["--version", &version]);
    }
    run_command(&mut command, &format!("install {id}"))
}

fn run_wsl_build(repo: &Path, profile: &str, distro: &str, plan: &BuildPlan) -> Result<(), String> {
    let mut update = Command::new("wsl.exe");
    update.args(["-d", distro, "-u", "root", "--", "apt-get", "update"]);
    run_command(&mut update, "WSL package index update")?;
    let mut install = Command::new("wsl.exe");
    install.args([
        "-d",
        distro,
        "-u",
        "root",
        "--",
        "env",
        "DEBIAN_FRONTEND=noninteractive",
        "apt-get",
        "install",
        "-y",
        "build-essential",
        "cargo",
        "clang",
        "llvm",
        "linux-libc-dev",
        "libssl-dev",
        "pkg-config",
        "make",
        "rustc",
        "iproute2",
        "python3",
        "ca-certificates",
    ]);
    run_command(&mut install, "WSL package installation")?;

    let mut cargo_check = Command::new("wsl.exe");
    cargo_check.args([
        "-d",
        distro,
        "--",
        "bash",
        "-lc",
        "command -v cargo && cargo --version",
    ]);
    run_command(&mut cargo_check, "WSL Cargo verification")?;

    let repo_string = repo.to_string_lossy().replace('\\', "/");
    let drive = repo_string
        .chars()
        .next()
        .ok_or_else(|| "repository path is empty".to_owned())?
        .to_ascii_lowercase();
    let wsl_repo = format!("/mnt/{}/{}", drive, &repo_string[3..]);
    let profile_flag = if profile == "release" {
        " --release"
    } else {
        ""
    };
    let tls = match plan.tls {
        Some(TlsMode::Psk) => " --features linux-bpf,tls-psk",
        Some(TlsMode::Rustls) => " --features linux-bpf,tls-rustls",
        None => " --features linux-bpf",
    };
    let command_line = format!(
        "cd '{wsl_repo}' && make -C crates/bpf PROFILE={profile} all && cargo build --locked{profile_flag} --target x86_64-unknown-linux-gnu -p shadow-socket-proxy-control{tls}"
    );
    let mut command = Command::new("wsl.exe");
    command.args(["-d", distro, "--", "bash", "-lc", &command_line]);
    run_command(&mut command, "WSL component build")
}

fn detected_version(command: &str, args: &[&str]) -> String {
    Command::new(command)
        .args(args)
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn detected_openssl_version() -> String {
    let executable = env::var_os("OPENSSL_DIR")
        .map(PathBuf::from)
        .map(|root| {
            root.join("bin").join(if cfg!(windows) {
                "openssl.exe"
            } else {
                "openssl"
            })
        })
        .filter(|path| path.exists())
        .unwrap_or_else(|| PathBuf::from("openssl"));
    Command::new(executable)
        .arg("version")
        .output()
        .ok()
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

fn cargo_build(
    repo: &Path,
    profile: &str,
    package: &str,
    features: Option<&str>,
    target: Option<&str>,
) -> Result<(), String> {
    let mut command = Command::new("cargo");
    command
        .current_dir(repo)
        .args(["build", "--locked", "-p", package]);
    if profile == "release" {
        command.arg("--release");
    }
    if let Some(target) = target {
        command.args(["--target", target]);
    }
    if let Some(features) = features {
        command.args(["--features", features]);
    }
    run_command(&mut command, &format!("{package} build"))
}

fn tls_feature(tls: Option<TlsMode>) -> Option<String> {
    tls.map(|mode| match mode {
        TlsMode::Psk => "tls-psk".to_owned(),
        TlsMode::Rustls => "tls-rustls".to_owned(),
    })
}

fn collect_if_exists(
    staging: &Path,
    name: &str,
    source: &Path,
    artifacts: &mut Vec<Artifact>,
) -> Result<(), String> {
    if !source.exists() {
        return Err(format!(
            "expected artifact was not produced: {}",
            source.display()
        ));
    }
    let destination = staging.join(name);
    fs::copy(source, &destination)
        .map_err(|error| format!("copy {}: {error}", source.display()))?;
    artifacts.push(Artifact {
        name: name.to_owned(),
        path: destination.to_string_lossy().into_owned(),
        sha256: sha256_file(&destination)?,
    });
    Ok(())
}

fn sha256_file(path: &Path) -> Result<String, String> {
    let mut file =
        fs::File::open(path).map_err(|error| format!("open {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 8192];
    loop {
        let count = file
            .read(&mut buffer)
            .map_err(|error| format!("read {}: {error}", path.display()))?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

struct WdkRoots {
    environment: Vec<(String, String)>,
    versions: Vec<String>,
    tools: Vec<String>,
}

fn discover_wdk() -> Result<WdkRoots, String> {
    let package_root = env::var("SSP_WSK_NUGET_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            env::var("USERPROFILE")
                .map(|home| PathBuf::from(home).join(".nuget").join("packages"))
                .unwrap_or_else(|_| PathBuf::from("."))
        });
    let wdk_root = env::var("SSP_WSK_WDK_ROOT").unwrap_or_else(|_| {
        package_root
            .join("microsoft.windows.wdk.x64")
            .join(WDK_VERSION)
            .join("c")
            .to_string_lossy()
            .into_owned()
    });
    let sdk_root = env::var("SSP_WSK_SDK_ROOT").unwrap_or_else(|_| {
        package_root
            .join("microsoft.windows.sdk.cpp")
            .join(WDK_VERSION)
            .join("c")
            .to_string_lossy()
            .into_owned()
    });
    if !Path::new(&wdk_root).exists() || !Path::new(&sdk_root).exists() {
        return Err(format!(
            "WDK/SDK packages are missing; expected `{wdk_root}` and `{sdk_root}`"
        ));
    }
    let signtool = env::var("SSP_SIGNTOOL").unwrap_or_default();
    let mut tools = Vec::new();
    if !signtool.is_empty() {
        tools.push(signtool);
    }
    Ok(WdkRoots {
        environment: vec![
            (
                "SSP_WSK_NUGET_ROOT".to_owned(),
                package_root.to_string_lossy().into_owned(),
            ),
            ("SSP_WSK_WDK_ROOT".to_owned(), wdk_root.clone()),
            ("SSP_WSK_SDK_ROOT".to_owned(), sdk_root),
            ("WDKContentRoot".to_owned(), wdk_root),
        ],
        versions: vec![format!("wdk-sdk={WDK_VERSION}")],
        tools,
    })
}

fn sign_driver(
    repo: &Path,
    staging: &Path,
    plan: &BuildPlan,
    artifacts: &mut Vec<Artifact>,
    tools: &mut Vec<String>,
) -> Result<(String, Option<String>, bool), String> {
    if !plan.kernel_relay {
        return Ok(("not-applicable".to_owned(), None, false));
    }
    let driver = artifacts
        .iter()
        .find(|artifact| artifact.name.ends_with(".dll"))
        .map(|artifact| PathBuf::from(&artifact.path))
        .ok_or_else(|| "kernel driver artifact was not produced".to_owned())?;
    if !plan.test_signing {
        return Ok(("unsigned".to_owned(), None, false));
    }
    let signtool = locate_signtool()?;
    if !signtool.exists() {
        return Err(format!("signtool does not exist: {}", signtool.display()));
    }
    tools.push(signtool.to_string_lossy().into_owned());
    let cert_dir = env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| repo.join("target"))
        .join("ShadowSocketProxy")
        .join("test-signing");
    fs::create_dir_all(&cert_dir)
        .map_err(|error| format!("create certificate directory: {error}"))?;
    let cert = cert_dir.join("shadow-socket-proxy-test.cer");
    let pfx = cert_dir.join("shadow-socket-proxy-test.pfx");
    let mut make_cert = Command::new(powershell_executable()?);
    make_cert.args([
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        &format!(
            "$c=New-SelfSignedCertificate -Type CodeSigningCert -Subject 'CN=ShadowSocketProxy Test' -CertStoreLocation Cert:\\CurrentUser\\My; Export-Certificate -Cert $c -FilePath '{}' ; Export-PfxCertificate -Cert $c -FilePath '{}' -Password (ConvertTo-SecureString -String 'ssp-test' -AsPlainText -Force)",
            cert.display(),
            pfx.display()
        ),
    ]);
    if !cert.exists() || !pfx.exists() {
        run_command(&mut make_cert, "create test certificate")?;
    }
    let mut sign = Command::new(&signtool);
    sign.args([
        "sign",
        "/fd",
        "SHA256",
        "/f",
        &pfx.to_string_lossy(),
        "/p",
        "ssp-test",
        &driver.to_string_lossy(),
    ]);
    run_command(&mut sign, "sign kernel driver")?;
    let mut verify = Command::new(&signtool);
    verify.args(["verify", "/pa", &driver.to_string_lossy()]);
    run_command(&mut verify, "verify kernel driver signature")?;
    let mut thumbprint_command = Command::new(powershell_executable()?);
    thumbprint_command.args([
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "(Get-ChildItem Cert:\\CurrentUser\\My | Where-Object Subject -eq 'CN=ShadowSocketProxy Test' | Select-Object -First 1 -ExpandProperty Thumbprint)",
    ]);
    let thumbprint = thumbprint_command
        .output()
        .ok()
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty());
    let _ = staging;
    Ok(("test-signed".to_owned(), thumbprint, false))
}

fn locate_signtool() -> Result<PathBuf, String> {
    if let Ok(path) = env::var("SSP_SIGNTOOL") {
        let path = PathBuf::from(path);
        if path.exists() {
            return Ok(path);
        }
    }
    let output = Command::new("where.exe")
        .arg("signtool.exe")
        .output()
        .map_err(|error| format!("locate signtool.exe: {error}"))?;
    if let Some(path) = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .find(|path| !path.is_empty())
    {
        return Ok(PathBuf::from(path));
    }
    for root in [
        env::var_os("SSP_WSK_WDK_ROOT").map(PathBuf::from),
        env::var_os("SSP_WSK_SDK_ROOT").map(PathBuf::from),
    ]
    .into_iter()
    .flatten()
    {
        if let Some(path) = find_file(&root, "signtool.exe") {
            return Ok(path);
        }
    }
    Err("test-signing requires signtool.exe; set SSP_SIGNTOOL or install the WDK".to_owned())
}

fn find_file(root: &Path, name: &str) -> Option<PathBuf> {
    let entries = fs::read_dir(root).ok()?;
    for entry in entries.flatten() {
        let path = entry.path();
        if path
            .file_name()
            .is_some_and(|file| file.eq_ignore_ascii_case(name))
        {
            return Some(path);
        }
        if path.is_dir() {
            if let Some(found) = find_file(&path, name) {
                return Some(found);
            }
        }
    }
    None
}

fn replace_file(source: &Path, destination: &Path) -> Result<(), String> {
    #[cfg(windows)]
    {
        let source_wide = source
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let destination_wide = destination
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let replaced = unsafe {
            MoveFileExW(
                source_wide.as_ptr(),
                destination_wide.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if replaced == 0 {
            return Err(format!(
                "publish manifest {} -> {} failed",
                source.display(),
                destination.display()
            ));
        }
        return Ok(());
    }
    #[cfg(not(windows))]
    {
        if destination.exists() {
            fs::remove_file(destination)
                .map_err(|error| format!("replace previous manifest: {error}"))?;
        }
        fs::rename(source, destination).map_err(|error| format!("publish manifest: {error}"))
    }
}

fn run_command(command: &mut Command, phase: &str) -> Result<(), String> {
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());
    let status = command
        .status()
        .map_err(|error| format!("{phase} could not start: {error}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("{phase} failed with {status}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(values: &[&str]) -> Result<BuildPlan, String> {
        parse_args(values.iter().map(|value| OsString::from(value)))
    }

    #[test]
    fn parses_valid_feature_plan() {
        let plan = parse(&[
            "build",
            "--release",
            "--features",
            "wsl",
            "tls-psk",
            "kernel-relay",
        ])
        .expect("valid plan");
        assert!(plan.release);
        assert!(plan.wsl);
        assert_eq!(plan.tls, Some(TlsMode::Psk));
        assert!(plan.kernel_relay);
    }

    #[test]
    fn accepts_feature_aliases_and_lists() {
        let plan = parse(&["build", "--features=tls_psk+wsl"]).expect("valid plan");
        assert_eq!(plan.tls, Some(TlsMode::Psk));
        assert!(plan.wsl);
    }

    #[test]
    fn rejects_conflicting_tls_modes() {
        let error = parse(&["build", "--features", "tls-psk,tls-rustls"]).unwrap_err();
        assert!(error.contains("mutually exclusive"));
    }

    #[test]
    fn rejects_test_signing_without_driver() {
        let error = parse(&["build", "--features", "test-signing"]).unwrap_err();
        assert!(error.contains("requires kernel-relay"));
    }

    #[test]
    fn rejects_unknown_features() {
        let error = parse(&["build", "--features", "wat"]).unwrap_err();
        assert!(error.contains("unknown feature"));
    }

    #[test]
    fn accepts_case_insensitive_msvc_environment_keys() {
        let environment = [
            ("Path".to_owned(), "path".to_owned()),
            ("Include".to_owned(), "include".to_owned()),
            ("Lib".to_owned(), "lib".to_owned()),
        ];
        assert!(["PATH", "INCLUDE", "LIB"].iter().all(|key| {
            environment
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case(key))
        }));
    }
}
