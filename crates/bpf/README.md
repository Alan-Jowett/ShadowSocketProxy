<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# Linux TC BPF artifact

`placeholder.bpf.c` is the Linux `SCHED_CLS` artifact source. The historical
filename is retained so existing packaging references remain valid; it is no
longer a placeholder. It exports:

- `ssp_tc_ingress_v3` and `ssp_tc_egress_v3`;
- `ssp_flow_index_v1`;
- `ssp_flow_state_v1`;
- `ssp_runtime_config_v3`;
- `ssp_tc_active_flows_v1`;
- `ssp_tc_counters_v1`.

Build on Linux with clang and kernel UAPI headers:

```sh
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I/usr/include/$(uname -m)-linux-gnu \
  -c placeholder.bpf.c -o shadow-socket-proxy.bpf.o
```

The control service validates all required v3 programs, flow maps, runtime
configuration ABI, and counter slots before attachment. It rejects stale v2
programs or destination-policy maps. Map `max_entries` values are fixed in the
ELF; active-flow capacity is an admission cap and does not resize or reattach
maps.

The source only rewrites bounds-checkable IPv4/IPv6 TCP/UDP first fragments.
Malformed, unsupported, non-initial-fragment, or unreadable packets return
`TC_ACT_OK` unchanged. Configured IPv4 and IPv6 targets are snapped per flow;
an unset family passes unchanged. TCP traffic to or from the authenticated
control listener bypasses rewriting, while UDP on the same port remains
eligible. RST removes a flow immediately; TCP FIN/ACK state is retained until
terminal grace, while UDP/QUIC activity is idle-TTL managed.

Kernel verifier, TC attachment, and `bpf_prog_test_run` tests are gated by
`SSP_TEST_BPF_ELF` and Linux kernel capabilities. They must not be used to
claim readiness on non-Linux hosts.

The Rust integration gate additionally accepts `SSP_TEST_BPF_PROG_RUN=1` and
`SSP_BPF_PROG_TEST_RUNNER`; the runner receives the ELF path and the ordered
fixtures `target-miss`, `flow-create`, `forward-rewrite`, `reverse-rewrite`,
`control-bypass`, `fin-ack-teardown`, and `rst`.
