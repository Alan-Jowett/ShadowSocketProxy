// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

#![cfg(target_os = "linux")]

use std::{env, process::Command};

const REQUIRED_SEQUENCE: &[&str] = &[
    "policy-miss",
    "flow-create",
    "forward-rewrite",
    "reverse-rewrite",
    "fin-ack-teardown",
    "rst",
];

#[test]
fn bpf_prog_test_run_sequence_is_explicitly_gated() {
    if env::var_os("SSP_TEST_BPF_PROG_RUN").is_none() {
        eprintln!(
            "skipped bpf_prog_test_run sequence: set SSP_TEST_BPF_PROG_RUN=1 to require the Linux runner"
        );
        return;
    }

    let elf = env::var_os("SSP_TEST_BPF_ELF")
        .expect("SSP_TEST_BPF_ELF is required when SSP_TEST_BPF_PROG_RUN=1");
    let runner = env::var_os("SSP_BPF_PROG_TEST_RUNNER")
        .expect("SSP_BPF_PROG_TEST_RUNNER must point to a runner using bpf_prog_test_run_opts");
    let status = Command::new(runner)
        .arg(elf)
        .args(
            REQUIRED_SEQUENCE
                .iter()
                .flat_map(|fixture| ["--fixture", fixture]),
        )
        .status()
        .expect("failed to start SSP_BPF_PROG_TEST_RUNNER");
    assert!(
        status.success(),
        "bpf_prog_test_run sequence runner failed: {status}"
    );
}
