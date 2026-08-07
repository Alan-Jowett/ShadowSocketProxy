// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

/*
 * Placeholder for the final TC ingress/egress packet-rewriting BPF program.
 * The control-service ABI is documented in the sibling Rust crate.
 *
 * An ELF supplied to the control service must export:
 *   - ssp_flow_map_v1
 *   - ssp_tc_ingress_v1
 *   - ssp_tc_egress_v1
 */
