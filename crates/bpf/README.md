<!-- SPDX-License-Identifier: MIT -->
<!-- Copyright (c) 2026 ShadowSocketProxy contributors -->

# Placeholder BPF ELF contract

The control service expects a supplied Linux BPF ELF to expose the following
ABI-v1 symbols:

- map: `ssp_flow_map_v1`;
- ingress TC classifier: `ssp_tc_ingress_v1`;
- egress TC classifier: `ssp_tc_egress_v1`.

The final packet-rewriting program is intentionally not part of this crate.
The map key and value byte layout is implemented in
`crates/control-service/src/mapping.rs` and is the contract used by the
production Aya backend adapter.

On Linux, `LinuxBpfBackend` uses Aya to load the ELF, validate these symbols,
attach ingress and egress links, and read or delete map entries. Attach
operations track service-owned links and roll back links created by a failed
multi-interface transaction. Non-Linux builds retain an explicit unsupported
adapter because TC and eBPF are Linux kernel facilities.
