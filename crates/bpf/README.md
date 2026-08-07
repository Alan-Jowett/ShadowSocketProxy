<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# Linux TC BPF artifact

`placeholder.bpf.c` is the Linux `SCHED_CLS` artifact source. The historical
filename is retained so existing packaging references remain valid; it is no
longer a placeholder. It exports:

- `ssp_tc_ingress_v2` and `ssp_tc_egress_v2`;
- `ssp_destination_policy_map_v1`;
- `ssp_flow_index_v1`;
- `ssp_flow_state_v1`;
- `ssp_runtime_config_v1`;
- `ssp_tc_active_flows_v1`;
- `ssp_tc_counters_v1`.

Build on Linux with clang and kernel UAPI headers:

```sh
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I/usr/include/$(uname -m)-linux-gnu \
  -c placeholder.bpf.c -o shadow-socket-proxy.bpf.o
```

The control service validates all required v2 programs and v1 maps before
attachment. Map `max_entries` values are fixed in the ELF; runtime policy and
flow capacities are admission caps and do not resize or reattach maps.

The source only rewrites bounds-checkable IPv4/IPv6 TCP/UDP first fragments.
Malformed, unsupported, non-initial-fragment, or unreadable packets return
`TC_ACT_OK` unchanged. RST removes a flow immediately; TCP FIN/ACK state is
retained until terminal grace, while UDP/QUIC activity is idle-TTL managed.

Kernel verifier, TC attachment, and `bpf_prog_test_run` tests are gated by
`SSP_TEST_BPF_ELF` and Linux kernel capabilities. They must not be used to
claim readiness on non-Linux hosts.

The Rust integration gate additionally accepts `SSP_TEST_BPF_PROG_RUN=1` and
`SSP_BPF_PROG_TEST_RUNNER`; the runner receives the ELF path and the ordered
fixtures `policy-miss`, `flow-create`, `forward-rewrite`, `reverse-rewrite`,
`fin-ack-teardown`, and `rst`.
