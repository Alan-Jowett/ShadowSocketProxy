// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors
//! Loads the TC BPF ELF and executes deterministic packet/map fixtures through
//! Aya's test-run API.

#[cfg(not(target_os = "linux"))]
/// Reports unsupported-platform status when the runner is built off Linux.
fn main() -> std::process::ExitCode {
    eprintln!("ssp-bpf-fixture-runner is only supported on Linux");
    std::process::ExitCode::FAILURE
}

#[cfg(target_os = "linux")]
/// Linux fixture implementation; it requires Aya, libc memlock, and BPF test-run.
mod linux {
    use aya::{
        maps::{Array, HashMap, MapData, MapError},
        programs::{SchedClassifier, TestRun, TestRunOptions},
        Ebpf,
    };
    use libc::{rlimit, RLIMIT_MEMLOCK, RLIM_INFINITY};
    use std::{
        ffi::OsStr,
        net::{Ipv4Addr, Ipv6Addr},
        path::{Path, PathBuf},
        process::ExitCode,
    };

    /// Map key/value ABI version expected by the fixture encoders.
    const MAP_ABI_VERSION: u16 = 1;
    /// Runtime-config schema version seeded into the BPF map.
    const RUNTIME_CONFIG_ABI_VERSION: u16 = 3;
    /// Encoded lifecycle value for an active flow.
    const FLOW_ACTIVE: u8 = 2;
    /// TCP protocol number used in fixture tuples.
    const PROTOCOL_TCP: u8 = 6;
    /// UDP protocol number used in fixture tuples.
    const PROTOCOL_UDP: u8 = 17;
    /// Flow-state protocol bit for TCP.
    const PROTOCOL_FLAG_TCP: u32 = 1;
    /// Flow-state protocol bit for UDP.
    const PROTOCOL_FLAG_UDP: u32 = 2;
    /// State bit set after observing a client SYN.
    const TCP_SYN_BIT: u32 = 1 << 0;
    /// State bit set after observing a server SYN/ACK.
    const TCP_SYN_ACK_BIT: u32 = 1 << 1;
    /// State bit set after FIN acknowledgement.
    const TCP_ACK_BIT: u32 = 1 << 2;
    /// State bit set after observing FIN.
    const TCP_FIN_BIT: u32 = 1 << 3;
    /// Wire TCP FIN flag.
    const TCP_FLAG_FIN: u8 = 0x01;
    /// Wire TCP SYN flag.
    const TCP_FLAG_SYN: u8 = 0x02;
    /// Wire TCP RST flag.
    const TCP_FLAG_RST: u8 = 0x04;
    /// Wire TCP ACK flag.
    const TCP_FLAG_ACK: u8 = 0x10;
    /// Ethernet header length expected by the packet builders.
    const ETH_HEADER_LEN: usize = 14;
    /// Fixed IPv4 header length emitted by the fixtures.
    const IPV4_HEADER_LEN: usize = 20;
    /// Fixed IPv6 header length emitted by the fixtures.
    const IPV6_HEADER_LEN: usize = 40;
    /// Minimum TCP header length emitted by the fixtures.
    const TCP_HEADER_LEN: usize = 20;
    /// UDP header length emitted by the fixtures.
    const UDP_HEADER_LEN: usize = 8;
    /// Idle TTL seeded into the runtime configuration fixture.
    const DEFAULT_IDLE_TTL_NS: u64 = 60 * 1_000 * 1_000 * 1_000;
    /// TCP terminal grace seeded into the runtime configuration fixture.
    const DEFAULT_TERMINAL_GRACE_NS: u64 = 30 * 1_000 * 1_000 * 1_000;
    /// Active-flow capacity seeded into the runtime configuration fixture.
    const DEFAULT_ACTIVE_FLOW_CAPACITY: u32 = 128;
    /// Control listener port excluded by the control-bypass fixture.
    const LISTENER_PORT: u16 = 50051;
    /// IPv4 packet-rewrite target port.
    const TARGET_PORT_V4: u16 = 8443;
    /// IPv6 packet-rewrite target port.
    const TARGET_PORT_V6: u16 = 5353;
    /// Counter index for packets with no family target.
    const COUNTER_TARGET_MISS: u32 = 0;
    /// Counter index for flow allocation failures.
    const COUNTER_FLOW_INSERT_FAILURE: u32 = 1;
    /// Counter index for control-listener bypasses.
    const COUNTER_CONTROL_BYPASS: u32 = 2;
    /// Ethernet type for IPv4.
    const ETH_P_IP: u16 = 0x0800;
    /// Ethernet type for IPv6.
    const ETH_P_IPV6: u16 = 0x86dd;
    /// Expected classifier return value for pass-through packets.
    const TC_ACT_OK: u32 = 0;
    /// Upper bound used when validating fixture selection.
    const MAX_FIXTURES: usize = 64;
    /// ELF program name for ingress rewriting.
    const INGRESS_PROGRAM_NAME: &str = "ssp_tc_ingress_v3";
    /// ELF program name for egress restoration.
    const EGRESS_PROGRAM_NAME: &str = "ssp_tc_egress_v3";
    /// ELF map containing tuple-to-flow indexes.
    const FLOW_INDEX_MAP_NAME: &str = "ssp_flow_index_v1";
    /// ELF map containing native flow state.
    const FLOW_STATE_MAP_NAME: &str = "ssp_flow_state_v1";
    /// ELF map containing runtime targets and timeouts.
    const RUNTIME_CONFIG_MAP_NAME: &str = "ssp_runtime_config_v3";
    /// ELF map containing packet-path counters.
    const COUNTERS_MAP_NAME: &str = "ssp_tc_counters_v1";
    /// ELF map tracking active-flow slot usage.
    const ACTIVE_FLOWS_MAP_NAME: &str = "ssp_tc_active_flows_v1";

    /// Maximum packet bytes stored by a fixture buffer.
    const PACKET_CAPACITY: usize = 256;
    /// Encoded tuple-key length.
    const TUPLE_KEY_LEN: usize = 40;
    /// Encoded tuple-index value length.
    const FLOW_INDEX_VALUE_LEN: usize = 16;
    /// Encoded flow-state key length.
    const FLOW_STATE_KEY_LEN: usize = 16;
    /// Encoded flow-state value length.
    const FLOW_STATE_VALUE_LEN: usize = 256;
    /// Encoded runtime-config value length.
    const RUNTIME_CONFIG_VALUE_LEN: usize = 80;
    /// Native counter word size used by the fixture maps.
    const WORD_LEN: usize = 8;

    /// Fixture operations return unit on failure after printing diagnostics.
    type RunnerResult<T = ()> = Result<T, ()>;
    /// Fixed-width encoded tuple key passed to Aya maps.
    type TupleKey = [u8; TUPLE_KEY_LEN];
    /// Fixed-width tuple-index value passed to Aya maps.
    type FlowIndexValue = [u8; FLOW_INDEX_VALUE_LEN];
    /// Fixed-width native flow-state key passed to Aya maps.
    type FlowStateKey = [u8; FLOW_STATE_KEY_LEN];
    /// Fixed-width native flow-state value passed to Aya maps.
    type FlowStateValue = [u8; FLOW_STATE_VALUE_LEN];
    /// Fixed-width runtime configuration value passed to Aya maps.
    type RuntimeConfigValue = [u8; RUNTIME_CONFIG_VALUE_LEN];
    /// Fixed-width native-endian counter slot.
    type CounterWord = [u8; WORD_LEN];

    #[derive(Clone, Copy)]
    /// Address family and its 16-byte ABI representation.
    struct IpAddrBytes {
        /// ABI family discriminator, 4 or 6.
        family: u8,
        /// IPv4-mapped or native IPv6 bytes.
        bytes: [u8; 16],
    }

    #[derive(Clone)]
    /// Zero-filled packet storage with an explicit valid prefix length.
    struct PacketBuffer {
        /// Backing storage supplied to Aya test runs.
        bytes: [u8; PACKET_CAPACITY],
        /// Number of initialized bytes in `bytes`.
        len: usize,
    }

    impl Default for PacketBuffer {
        /// Creates an empty zero-filled packet buffer.
        fn default() -> Self {
            Self {
                bytes: [0; PACKET_CAPACITY],
                len: 0,
            }
        }
    }

    impl PacketBuffer {
        /// Borrows only the initialized packet prefix.
        fn as_slice(&self) -> &[u8] {
            &self.bytes[..self.len]
        }
    }

    /// Loaded BPF object retained while a fixture executes.
    struct BpfFixture {
        /// Aya object containing programs and seeded maps.
        bpf: Ebpf,
    }

    /// Named command-line fixture and its runner function.
    struct FixtureDef {
        /// Stable fixture selector shown in usage and diagnostics.
        name: &'static str,
        /// Function that runs the fixture against an ELF path.
        run: fn(&Path) -> RunnerResult,
    }

    /// Registry of packet rewrite, lifecycle, bypass, and failure fixtures.
    static FIXTURES: &[FixtureDef] = &[
        FixtureDef {
            name: "target-miss",
            run: run_target_miss_fixture,
        },
        FixtureDef {
            name: "flow-create",
            run: run_flow_create_fixture,
        },
        FixtureDef {
            name: "forward-rewrite",
            run: run_forward_rewrite_fixture,
        },
        FixtureDef {
            name: "reverse-rewrite",
            run: run_reverse_rewrite_fixture,
        },
        FixtureDef {
            name: "control-bypass",
            run: run_control_bypass_fixture,
        },
        FixtureDef {
            name: "fin-ack-teardown",
            run: run_fin_ack_teardown_fixture,
        },
        FixtureDef {
            name: "rst",
            run: run_rst_fixture,
        },
    ];

    /// Parses fixture selection, configures memlock, runs requested fixtures,
    /// and returns a shell-friendly exit code.
    pub fn main() -> ExitCode {
        let args: Vec<_> = std::env::args_os().collect();
        if args.len() < 4 {
            usage(args.first().map(|arg0| arg0.as_os_str()));
            return ExitCode::from(2);
        }
        if set_memlock_limit().is_err() {
            return ExitCode::FAILURE;
        }

        let elf_path = PathBuf::from(&args[1]);
        let mut fixture_names = Vec::with_capacity(args.len().saturating_sub(2) / 2);
        let mut index = 2;
        while index < args.len() {
            if args[index].as_os_str() != OsStr::new("--fixture") {
                usage(args.first().map(|arg0| arg0.as_os_str()));
                return ExitCode::from(2);
            }
            index += 1;
            if index >= args.len() {
                usage(args.first().map(|arg0| arg0.as_os_str()));
                return ExitCode::from(2);
            }
            if fixture_names.len() >= MAX_FIXTURES {
                eprintln!("too many fixtures requested");
                return ExitCode::from(2);
            }
            fixture_names.push(args[index].to_string_lossy().into_owned());
            index += 1;
        }

        if fixture_names.is_empty() {
            usage(args.first().map(|arg0| arg0.as_os_str()));
            return ExitCode::from(2);
        }

        for fixture_name in &fixture_names {
            let Some(fixture) = find_fixture(fixture_name) else {
                eprintln!("unknown fixture: {fixture_name}");
                usage(args.first().map(|arg0| arg0.as_os_str()));
                return ExitCode::from(2);
            };
            if (fixture.run)(&elf_path).is_err() {
                eprintln!("fixture {} failed", fixture.name);
                return ExitCode::FAILURE;
            }
            println!("fixture {} passed", fixture.name);
        }

        ExitCode::SUCCESS
    }

    impl BpfFixture {
        /// Loads the ELF and retains its programs/maps for one fixture run.
        fn open(elf_path: &Path) -> RunnerResult<Self> {
            let mut bpf = match Ebpf::load_file(elf_path) {
                Ok(bpf) => bpf,
                Err(error) => {
                    eprintln!("failed to open BPF ELF {}: {error}", elf_path.display());
                    return Err(());
                }
            };

            Self::load_program(&mut bpf, elf_path, INGRESS_PROGRAM_NAME)?;
            Self::load_program(&mut bpf, elf_path, EGRESS_PROGRAM_NAME)?;

            for map_name in [
                FLOW_INDEX_MAP_NAME,
                FLOW_STATE_MAP_NAME,
                RUNTIME_CONFIG_MAP_NAME,
                COUNTERS_MAP_NAME,
                ACTIVE_FLOWS_MAP_NAME,
            ] {
                if bpf.map_mut(map_name).is_none() {
                    eprintln!("required map {map_name} is missing");
                    return Err(());
                }
            }

            Ok(Self { bpf })
        }

        /// Loads and verifies one TC classifier by its ELF program name.
        fn load_program(bpf: &mut Ebpf, elf_path: &Path, program_name: &str) -> RunnerResult {
            let program = match bpf.program_mut(program_name) {
                Some(program) => program,
                None => {
                    eprintln!(
                        "required {} program {program_name} is missing",
                        if program_name == INGRESS_PROGRAM_NAME {
                            "ingress"
                        } else {
                            "egress"
                        }
                    );
                    return Err(());
                }
            };
            let classifier: &mut SchedClassifier = match program.try_into() {
                Ok(classifier) => classifier,
                Err(error) => {
                    eprintln!(
                        "failed to interpret BPF program {program_name} from {}: {error}",
                        elf_path.display()
                    );
                    return Err(());
                }
            };
            if let Err(error) = classifier.load() {
                eprintln!("failed to load BPF ELF {}: {error}", elf_path.display());
                return Err(());
            }
            Ok(())
        }

        /// Initializes runtime config and clears fixture-observed map state.
        fn seed_maps(&mut self, config: &RuntimeConfigValue) -> RunnerResult {
            self.with_runtime_map(|map| {
                map.set(0, *config, 0).map_err(|error| {
                    eprintln!("failed to seed runtime config map: {error}");
                })?;
                Ok(())
            })?;

            self.with_counters_map(|map| {
                let zero = 0u64.to_le_bytes();
                for slot in 0..3 {
                    map.set(slot, zero, 0).map_err(|error| {
                        eprintln!("failed to zero counter slot {slot}: {error}");
                    })?;
                }
                Ok(())
            })?;

            self.with_active_flows_map(|map| {
                let zero = 0u64.to_le_bytes();
                map.set(0, zero, 0).map_err(|error| {
                    eprintln!("failed to zero active-flow counter: {error}");
                })?;
                Ok(())
            })
        }

        /// Executes a classifier against one packet and returns its TC action.
        fn run_program(
            &mut self,
            label: &str,
            program_name: &str,
            input: &PacketBuffer,
            expected: &PacketBuffer,
        ) -> RunnerResult {
            let mut output = [0u8; PACKET_CAPACITY];
            let result = {
                let program = match self.bpf.program_mut(program_name) {
                    Some(program) => program,
                    None => {
                        eprintln!("required program {program_name} is missing");
                        return Err(());
                    }
                };
                let classifier: &mut SchedClassifier = match program.try_into() {
                    Ok(classifier) => classifier,
                    Err(error) => {
                        eprintln!("failed to interpret BPF program {program_name}: {error}");
                        return Err(());
                    }
                };
                classifier.test_run(TestRunOptions {
                    data_in: Some(input.as_slice()),
                    data_out: Some(&mut output),
                    repeat: 1,
                    ..Default::default()
                })
            };

            let result = match result {
                Ok(result) => result,
                Err(error) => {
                    eprintln!("{label} failed during bpf_prog_test_run_opts: {error}");
                    return Err(());
                }
            };

            if result.return_value != TC_ACT_OK {
                eprintln!(
                    "{label} returned unexpected TC action {}",
                    result.return_value
                );
                return Err(());
            }

            require_packet_equal(label, expected, &output[..result.data_size_out as usize])
        }

        /// Reads one native-endian counter slot from the counters map.
        fn read_counter(&mut self, slot: u32) -> RunnerResult<u64> {
            self.with_counters_map(|map| {
                map.get(&slot, 0).map(u64::from_le_bytes).map_err(|error| {
                    eprintln!("failed to read counter slot {slot}: {error}");
                })
            })
        }

        /// Reads the active-flow slot counter used by capacity assertions.
        fn read_active_flows(&mut self) -> RunnerResult<u64> {
            self.with_active_flows_map(|map| {
                map.get(&0, 0).map(u64::from_le_bytes).map_err(|error| {
                    eprintln!("failed to read active-flow count: {error}");
                })
            })
        }

        /// Counts tuple indexes currently owned by the flow-index map.
        fn count_flow_index_entries(&mut self) -> RunnerResult<usize> {
            self.with_flow_index_map(count_hash_entries)
        }

        /// Counts native flow-state records currently stored in the state map.
        fn count_flow_state_entries(&mut self) -> RunnerResult<usize> {
            self.with_flow_state_map(count_hash_entries)
        }

        /// Looks up a tuple index and decodes its flow id/generation bytes.
        fn lookup_flow_index(&mut self, key: &TupleKey) -> RunnerResult<Option<FlowIndexValue>> {
            self.with_flow_index_map(|map| {
                optional_lookup(map, key, "failed to read flow index entry")
            })
        }

        /// Looks up a native flow-state value by id and generation.
        fn lookup_flow_state(
            &mut self,
            key: &FlowStateKey,
        ) -> RunnerResult<Option<FlowStateValue>> {
            self.with_flow_state_map(|map| {
                optional_lookup(map, key, "failed to read flow state entry")
            })
        }

        /// Borrows the flow-index map for one fallible closure.
        fn with_flow_index_map<T>(
            &mut self,
            operation: impl FnOnce(
                &mut HashMap<&mut MapData, TupleKey, FlowIndexValue>,
            ) -> RunnerResult<T>,
        ) -> RunnerResult<T> {
            let map = match self.bpf.map_mut(FLOW_INDEX_MAP_NAME) {
                Some(map) => map,
                None => {
                    eprintln!("required map {FLOW_INDEX_MAP_NAME} is missing");
                    return Err(());
                }
            };
            let mut map = HashMap::try_from(map).map_err(|error| {
                eprintln!("failed to open flow-index map: {error}");
            })?;
            operation(&mut map)
        }

        /// Borrows the flow-state map for one fallible closure.
        fn with_flow_state_map<T>(
            &mut self,
            operation: impl FnOnce(
                &mut HashMap<&mut MapData, FlowStateKey, FlowStateValue>,
            ) -> RunnerResult<T>,
        ) -> RunnerResult<T> {
            let map = match self.bpf.map_mut(FLOW_STATE_MAP_NAME) {
                Some(map) => map,
                None => {
                    eprintln!("required map {FLOW_STATE_MAP_NAME} is missing");
                    return Err(());
                }
            };
            let mut map = HashMap::try_from(map).map_err(|error| {
                eprintln!("failed to open flow-state map: {error}");
            })?;
            operation(&mut map)
        }

        /// Borrows the runtime-config map for one fallible closure.
        fn with_runtime_map<T>(
            &mut self,
            operation: impl FnOnce(&mut Array<&mut MapData, RuntimeConfigValue>) -> RunnerResult<T>,
        ) -> RunnerResult<T> {
            let map = match self.bpf.map_mut(RUNTIME_CONFIG_MAP_NAME) {
                Some(map) => map,
                None => {
                    eprintln!("required map {RUNTIME_CONFIG_MAP_NAME} is missing");
                    return Err(());
                }
            };
            let mut map = Array::try_from(map).map_err(|error| {
                eprintln!("failed to open runtime-config map: {error}");
            })?;
            operation(&mut map)
        }

        /// Borrows the counters map for one fallible closure.
        fn with_counters_map<T>(
            &mut self,
            operation: impl FnOnce(&mut Array<&mut MapData, CounterWord>) -> RunnerResult<T>,
        ) -> RunnerResult<T> {
            let map = match self.bpf.map_mut(COUNTERS_MAP_NAME) {
                Some(map) => map,
                None => {
                    eprintln!("required map {COUNTERS_MAP_NAME} is missing");
                    return Err(());
                }
            };
            let mut map = Array::try_from(map).map_err(|error| {
                eprintln!("failed to open counters map: {error}");
            })?;
            operation(&mut map)
        }

        /// Borrows the active-flow array for one fallible closure.
        fn with_active_flows_map<T>(
            &mut self,
            operation: impl FnOnce(&mut Array<&mut MapData, CounterWord>) -> RunnerResult<T>,
        ) -> RunnerResult<T> {
            let map = match self.bpf.map_mut(ACTIVE_FLOWS_MAP_NAME) {
                Some(map) => map,
                None => {
                    eprintln!("required map {ACTIVE_FLOWS_MAP_NAME} is missing");
                    return Err(());
                }
            };
            let mut map = Array::try_from(map).map_err(|error| {
                eprintln!("failed to open active-flows map: {error}");
            })?;
            operation(&mut map)
        }
    }

    /// Returns a map value when present and converts missing values to `None`.
    fn optional_lookup<K, V>(
        map: &mut HashMap<&mut MapData, K, V>,
        key: &K,
        label: &str,
    ) -> RunnerResult<Option<V>>
    where
        K: aya::Pod,
        V: aya::Pod,
    {
        match map.get(key, 0) {
            Ok(value) => Ok(Some(value)),
            Err(MapError::KeyNotFound) | Err(MapError::ElementNotFound) => Ok(None),
            Err(error) => {
                eprintln!("{label}: {error}");
                Err(())
            }
        }
    }

    /// Counts entries in a hash map without mutating it.
    fn count_hash_entries<K, V>(map: &mut HashMap<&mut MapData, K, V>) -> RunnerResult<usize>
    where
        K: aya::Pod,
        V: aya::Pod,
    {
        let mut count = 0usize;
        for entry in map.iter() {
            entry.map_err(|error| {
                eprintln!("failed to iterate map keys: {error}");
            })?;
            count += 1;
        }
        Ok(count)
    }

    /// Prints command usage and the registered fixture names.
    fn usage(argv0: Option<&OsStr>) {
        let program = argv0
            .map(|value| value.to_string_lossy())
            .unwrap_or_else(|| "ssp-bpf-fixture-runner".into());
        eprintln!(
            "usage: {} <bpf-elf> --fixture <name> [--fixture <name> ...]\nfixtures: target-miss, flow-create, forward-rewrite, reverse-rewrite,\n          control-bypass, fin-ack-teardown, rst",
            program
        );
    }

    /// Raises RLIMIT_MEMLOCK so the kernel can load the fixture maps.
    fn set_memlock_limit() -> RunnerResult {
        let limit = rlimit {
            rlim_cur: RLIM_INFINITY,
            rlim_max: RLIM_INFINITY,
        };
        let result = unsafe { libc::setrlimit(RLIMIT_MEMLOCK, &limit) };
        if result != 0 {
            eprintln!(
                "failed to raise RLIMIT_MEMLOCK: {}",
                std::io::Error::last_os_error()
            );
            return Err(());
        }
        Ok(())
    }

    /// Parses an IPv4/IPv6 literal into the fixture ABI representation.
    fn parse_ip(text: &str) -> RunnerResult<IpAddrBytes> {
        let mut bytes = [0u8; 16];
        if let Ok(address) = text.parse::<Ipv4Addr>() {
            bytes[12..16].copy_from_slice(&address.octets());
            return Ok(IpAddrBytes { family: 4, bytes });
        }
        if let Ok(address) = text.parse::<Ipv6Addr>() {
            bytes.copy_from_slice(&address.octets());
            return Ok(IpAddrBytes { family: 6, bytes });
        }
        eprintln!("invalid IP address literal: {text}");
        Err(())
    }

    /// Produces the 16-byte IPv4-mapped or native IPv6 representation.
    fn mapped_ip_bytes(address: &IpAddrBytes) -> [u8; 16] {
        if address.family == 4 {
            let mut output = [0u8; 16];
            output[10] = 0xff;
            output[11] = 0xff;
            output[12..16].copy_from_slice(&address.bytes[12..16]);
            output
        } else {
            address.bytes
        }
    }

    /// Writes a big-endian 16-bit field into a packet buffer.
    fn write_be16(target: &mut [u8], value: u16) {
        target[..2].copy_from_slice(&value.to_be_bytes());
    }

    /// Writes a big-endian 32-bit field into a packet buffer.
    fn write_be32(target: &mut [u8], value: u32) {
        target[..4].copy_from_slice(&value.to_be_bytes());
    }

    /// Adds a one-complement word to a packet checksum accumulator.
    fn checksum_add(mut sum: u32, data: &[u8]) -> u32 {
        let mut chunks = data.chunks_exact(2);
        for chunk in &mut chunks {
            sum += ((chunk[0] as u32) << 8) | chunk[1] as u32;
        }
        if let Some(byte) = chunks.remainder().first() {
            sum += (*byte as u32) << 8;
        }
        sum
    }

    /// Folds a checksum accumulator and returns its network-order checksum.
    fn checksum_finish(mut sum: u32) -> u16 {
        while (sum >> 16) != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Computes the checksum for an IPv4 header in the supplied packet.
    fn ipv4_header_checksum(header: &[u8]) -> u16 {
        checksum_finish(checksum_add(0, &header[..IPV4_HEADER_LEN]))
    }

    /// Computes a TCP/UDP checksum over an IPv4 pseudo-header and payload.
    fn ipv4_transport_checksum(
        source: &IpAddrBytes,
        destination: &IpAddrBytes,
        protocol: u8,
        segment: &[u8],
    ) -> u16 {
        let mut sum = 0u32;
        sum = checksum_add(sum, &source.bytes[12..16]);
        sum = checksum_add(sum, &destination.bytes[12..16]);
        sum += protocol as u32;
        sum += segment.len() as u32;
        sum = checksum_add(sum, segment);
        checksum_finish(sum)
    }

    /// Computes a TCP/UDP checksum over an IPv6 pseudo-header and payload.
    fn ipv6_transport_checksum(
        source: &IpAddrBytes,
        destination: &IpAddrBytes,
        protocol: u8,
        segment: &[u8],
    ) -> u16 {
        let mut sum = 0u32;
        let length_bytes = (segment.len() as u32).to_be_bytes();
        sum = checksum_add(sum, &source.bytes);
        sum = checksum_add(sum, &destination.bytes);
        sum = checksum_add(sum, &length_bytes);
        sum += protocol as u32;
        sum = checksum_add(sum, segment);
        checksum_finish(sum)
    }

    /// Writes the fixed Ethernet header used by all packet fixtures.
    fn fill_ethernet_header(frame: &mut [u8], ether_type: u16) {
        const DESTINATION: [u8; 6] = [0x02, 0x10, 0x20, 0x30, 0x40, 0x50];
        const SOURCE: [u8; 6] = [0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee];

        frame[..6].copy_from_slice(&DESTINATION);
        frame[6..12].copy_from_slice(&SOURCE);
        write_be16(&mut frame[12..14], ether_type);
    }

    #[allow(clippy::too_many_arguments)]
    /// Builds an Ethernet/IPv4/TCP packet with valid checksums and flags.
    fn build_ipv4_tcp_packet(
        packet: &mut PacketBuffer,
        source: &IpAddrBytes,
        destination: &IpAddrBytes,
        source_port: u16,
        destination_port: u16,
        flags: u8,
        sequence_number: u32,
        acknowledgment_number: u32,
    ) {
        *packet = PacketBuffer::default();
        packet.len = ETH_HEADER_LEN + IPV4_HEADER_LEN + TCP_HEADER_LEN;

        let frame = &mut packet.bytes[..packet.len];
        fill_ethernet_header(frame, ETH_P_IP);

        let ip = &mut frame[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN];
        ip[0] = 0x45;
        ip[1] = 0;
        write_be16(&mut ip[2..4], (IPV4_HEADER_LEN + TCP_HEADER_LEN) as u16);
        write_be16(&mut ip[4..6], 0x1234);
        write_be16(&mut ip[6..8], 0);
        ip[8] = 64;
        ip[9] = PROTOCOL_TCP;
        ip[12..16].copy_from_slice(&source.bytes[12..16]);
        ip[16..20].copy_from_slice(&destination.bytes[12..16]);
        let checksum = ipv4_header_checksum(ip);
        write_be16(&mut ip[10..12], checksum);

        let tcp = &mut frame[ETH_HEADER_LEN + IPV4_HEADER_LEN..packet.len];
        write_be16(&mut tcp[0..2], source_port);
        write_be16(&mut tcp[2..4], destination_port);
        write_be32(&mut tcp[4..8], sequence_number);
        write_be32(&mut tcp[8..12], acknowledgment_number);
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        write_be16(&mut tcp[14..16], 4096);
        let checksum = ipv4_transport_checksum(source, destination, PROTOCOL_TCP, tcp);
        write_be16(&mut tcp[16..18], checksum);
    }

    #[allow(clippy::too_many_arguments)]
    /// Builds an Ethernet/IPv6/TCP packet with valid checksums and flags.
    fn build_ipv6_tcp_packet(
        packet: &mut PacketBuffer,
        source: &IpAddrBytes,
        destination: &IpAddrBytes,
        source_port: u16,
        destination_port: u16,
        flags: u8,
        sequence_number: u32,
        acknowledgment_number: u32,
    ) {
        *packet = PacketBuffer::default();
        packet.len = ETH_HEADER_LEN + IPV6_HEADER_LEN + TCP_HEADER_LEN;

        let frame = &mut packet.bytes[..packet.len];
        fill_ethernet_header(frame, ETH_P_IPV6);

        let ip6 = &mut frame[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV6_HEADER_LEN];
        ip6[0] = 0x60;
        write_be16(&mut ip6[4..6], TCP_HEADER_LEN as u16);
        ip6[6] = PROTOCOL_TCP;
        ip6[7] = 64;
        ip6[8..24].copy_from_slice(&source.bytes);
        ip6[24..40].copy_from_slice(&destination.bytes);

        let tcp = &mut frame[ETH_HEADER_LEN + IPV6_HEADER_LEN..packet.len];
        write_be16(&mut tcp[0..2], source_port);
        write_be16(&mut tcp[2..4], destination_port);
        write_be32(&mut tcp[4..8], sequence_number);
        write_be32(&mut tcp[8..12], acknowledgment_number);
        tcp[12] = 5 << 4;
        tcp[13] = flags;
        write_be16(&mut tcp[14..16], 4096);
        let checksum = ipv6_transport_checksum(source, destination, PROTOCOL_TCP, tcp);
        write_be16(&mut tcp[16..18], checksum);
    }

    /// Builds an Ethernet/IPv4/UDP packet with a valid checksum.
    fn build_ipv4_udp_packet(
        packet: &mut PacketBuffer,
        source: &IpAddrBytes,
        destination: &IpAddrBytes,
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) {
        *packet = PacketBuffer::default();
        let udp_length = UDP_HEADER_LEN + payload.len();
        packet.len = ETH_HEADER_LEN + IPV4_HEADER_LEN + udp_length;

        let frame = &mut packet.bytes[..packet.len];
        fill_ethernet_header(frame, ETH_P_IP);

        let ip = &mut frame[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN];
        ip[0] = 0x45;
        ip[1] = 0;
        write_be16(&mut ip[2..4], (IPV4_HEADER_LEN + udp_length) as u16);
        write_be16(&mut ip[4..6], 0x5678);
        write_be16(&mut ip[6..8], 0);
        ip[8] = 64;
        ip[9] = PROTOCOL_UDP;
        ip[12..16].copy_from_slice(&source.bytes[12..16]);
        ip[16..20].copy_from_slice(&destination.bytes[12..16]);
        let checksum = ipv4_header_checksum(ip);
        write_be16(&mut ip[10..12], checksum);

        let udp = &mut frame[ETH_HEADER_LEN + IPV4_HEADER_LEN..packet.len];
        write_be16(&mut udp[0..2], source_port);
        write_be16(&mut udp[2..4], destination_port);
        write_be16(&mut udp[4..6], udp_length as u16);
        udp[UDP_HEADER_LEN..].copy_from_slice(payload);
        let mut checksum = ipv4_transport_checksum(source, destination, PROTOCOL_UDP, udp);
        if checksum == 0 {
            checksum = 0xffff;
        }
        write_be16(&mut udp[6..8], checksum);
    }

    /// Builds an Ethernet/IPv6/UDP packet with a valid checksum.
    fn build_ipv6_udp_packet(
        packet: &mut PacketBuffer,
        source: &IpAddrBytes,
        destination: &IpAddrBytes,
        source_port: u16,
        destination_port: u16,
        payload: &[u8],
    ) {
        *packet = PacketBuffer::default();
        let udp_length = UDP_HEADER_LEN + payload.len();
        packet.len = ETH_HEADER_LEN + IPV6_HEADER_LEN + udp_length;

        let frame = &mut packet.bytes[..packet.len];
        fill_ethernet_header(frame, ETH_P_IPV6);

        let ip6 = &mut frame[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV6_HEADER_LEN];
        ip6[0] = 0x60;
        write_be16(&mut ip6[4..6], udp_length as u16);
        ip6[6] = PROTOCOL_UDP;
        ip6[7] = 64;
        ip6[8..24].copy_from_slice(&source.bytes);
        ip6[24..40].copy_from_slice(&destination.bytes);

        let udp = &mut frame[ETH_HEADER_LEN + IPV6_HEADER_LEN..packet.len];
        write_be16(&mut udp[0..2], source_port);
        write_be16(&mut udp[2..4], destination_port);
        write_be16(&mut udp[4..6], udp_length as u16);
        udp[UDP_HEADER_LEN..].copy_from_slice(payload);
        let mut checksum = ipv6_transport_checksum(source, destination, PROTOCOL_UDP, udp);
        if checksum == 0 {
            checksum = 0xffff;
        }
        write_be16(&mut udp[6..8], checksum);
    }

    /// Prints a compact packet dump for fixture failure diagnostics.
    fn dump_packet(label: &str, packet: &[u8]) {
        eprintln!("{label} ({} bytes):", packet.len());
        for (index, byte) in packet.iter().enumerate() {
            if index % 16 == 0 {
                eprint!("  {index:04x}:");
            }
            eprint!(" {byte:02x}");
            if index % 16 == 15 || index + 1 == packet.len() {
                eprintln!();
            }
        }
    }

    /// Fails the fixture with a byte-level diff when packets differ.
    fn require_packet_equal(label: &str, expected: &PacketBuffer, actual: &[u8]) -> RunnerResult {
        if actual != expected.as_slice() {
            eprintln!("{label} packet mismatch");
            dump_packet("expected", expected.as_slice());
            dump_packet("actual", actual);
            return Err(());
        }
        Ok(())
    }

    /// Encodes a fixture tuple into the BPF tuple-index layout.
    fn make_tuple_key(
        source: &IpAddrBytes,
        destination: &IpAddrBytes,
        protocol: u8,
        source_port: u16,
        destination_port: u16,
    ) -> TupleKey {
        let mut key = [0u8; TUPLE_KEY_LEN];
        key[0..2].copy_from_slice(&MAP_ABI_VERSION.to_be_bytes());
        key[2] = source.family;
        key[3] = protocol;
        key[4..20].copy_from_slice(&mapped_ip_bytes(source));
        key[20..36].copy_from_slice(&mapped_ip_bytes(destination));
        key[36..38].copy_from_slice(&source_port.to_be_bytes());
        key[38..40].copy_from_slice(&destination_port.to_be_bytes());
        key
    }

    /// Encodes a flow id/generation pair into the state-map key layout.
    fn make_flow_state_key(flow_id: u64, generation: u32) -> FlowStateKey {
        let mut key = [0u8; FLOW_STATE_KEY_LEN];
        key[0..2].copy_from_slice(&MAP_ABI_VERSION.to_be_bytes());
        key[4..12].copy_from_slice(&flow_id.to_ne_bytes());
        key[12..16].copy_from_slice(&generation.to_ne_bytes());
        key
    }

    /// Computes the same stable tuple hash used for fixture map keys.
    fn tuple_hash(key: &TupleKey) -> u64 {
        let mut hash = 1_469_598_103_934_665_603u64;
        for byte in key {
            hash = (hash ^ (*byte as u64)).wrapping_mul(1_099_511_628_211);
        }
        if hash == 0 {
            1
        } else {
            hash
        }
    }

    /// Creates runtime config bytes with both family targets disabled.
    fn init_runtime_config() -> RuntimeConfigValue {
        let mut config = [0u8; RUNTIME_CONFIG_VALUE_LEN];
        config[0..2].copy_from_slice(&RUNTIME_CONFIG_ABI_VERSION.to_be_bytes());
        config[28] = 4;
        config[29] = 1;
        config[46..48].copy_from_slice(&LISTENER_PORT.to_be_bytes());
        config[48..56].copy_from_slice(&DEFAULT_IDLE_TTL_NS.to_le_bytes());
        config[56..64].copy_from_slice(&DEFAULT_TERMINAL_GRACE_NS.to_le_bytes());
        config[64..68].copy_from_slice(&DEFAULT_ACTIVE_FLOW_CAPACITY.to_le_bytes());
        config
    }

    /// Enables and writes the IPv4 target address and port fields.
    fn set_ipv4_target(config: &mut RuntimeConfigValue, address: &IpAddrBytes) {
        config[2] = 1;
        config[4..8].copy_from_slice(&address.bytes[12..16]);
        config[8..10].copy_from_slice(&TARGET_PORT_V4.to_be_bytes());
    }

    /// Enables and writes the IPv6 target address and port fields.
    fn set_ipv6_target(config: &mut RuntimeConfigValue, address: &IpAddrBytes) {
        config[3] = 1;
        config[10..26].copy_from_slice(&address.bytes);
        config[26..28].copy_from_slice(&TARGET_PORT_V6.to_be_bytes());
    }

    /// Reads a big-endian 16-bit field from fixture bytes.
    fn read_u16_be(bytes: &[u8], start: usize) -> u16 {
        u16::from_be_bytes(bytes[start..start + 2].try_into().unwrap())
    }

    /// Reads a native-endian 32-bit field from fixture bytes.
    fn read_u32_ne(bytes: &[u8], start: usize) -> u32 {
        u32::from_ne_bytes(bytes[start..start + 4].try_into().unwrap())
    }

    /// Reads a native-endian 64-bit field from fixture bytes.
    fn read_u64_ne(bytes: &[u8], start: usize) -> u64 {
        u64::from_ne_bytes(bytes[start..start + 8].try_into().unwrap())
    }

    /// Asserts an observed counter/value equals the expected number.
    fn expect_equal_u64(label: &str, actual: u64, expected: u64) -> RunnerResult {
        if actual != expected {
            eprintln!("{label} mismatch: expected {expected}, got {actual}");
            return Err(());
        }
        Ok(())
    }

    /// Asserts a fixture predicate and prints a diagnostic on failure.
    fn expect_true(label: &str, condition: bool) -> RunnerResult {
        if !condition {
            eprintln!("{label} failed");
            return Err(());
        }
        Ok(())
    }

    /// Asserts that encoded tuple fields match the expected tuple.
    fn expect_tuple_equal(label: &str, actual: &TupleKey, expected: &TupleKey) -> RunnerResult {
        if actual != expected {
            eprintln!("{label} tuple mismatch");
            return Err(());
        }
        Ok(())
    }

    /// Asserts that a tuple index points at the expected flow generation.
    fn expect_index_owner(
        label: &str,
        index_value: &FlowIndexValue,
        flow_id: u64,
        generation: u32,
    ) -> RunnerResult {
        let version = read_u16_be(index_value, 0);
        let actual_flow_id = read_u64_ne(index_value, 4);
        let actual_generation = read_u32_ne(index_value, 12);
        if version != MAP_ABI_VERSION
            || actual_flow_id != flow_id
            || actual_generation != generation
        {
            eprintln!(
                "{label} owner mismatch: version={version} flow_id={actual_flow_id} generation={actual_generation}"
            );
            return Err(());
        }
        Ok(())
    }

    /// Extracts one encoded tuple from a native flow-state value.
    fn flow_state_tuple(value: &FlowStateValue, start: usize) -> TupleKey {
        value[start..start + TUPLE_KEY_LEN].try_into().unwrap()
    }

    /// Verifies that all packet counters and flow counts start at zero.
    fn assert_zero_counts(fixture: &mut BpfFixture) -> RunnerResult {
        expect_equal_u64(
            "flow-index count",
            fixture.count_flow_index_entries()? as u64,
            0,
        )?;
        expect_equal_u64(
            "flow-state count",
            fixture.count_flow_state_entries()? as u64,
            0,
        )?;
        expect_equal_u64("active-flow count", fixture.read_active_flows()?, 0)
    }

    /// Verifies the three packet counters after a fixture action.
    fn assert_counter_values(
        fixture: &mut BpfFixture,
        target_misses: u64,
        flow_insert_failures: u64,
        control_bypasses: u64,
    ) -> RunnerResult {
        expect_equal_u64(
            "target-miss counter",
            fixture.read_counter(COUNTER_TARGET_MISS)?,
            target_misses,
        )?;
        expect_equal_u64(
            "flow-insert-failure counter",
            fixture.read_counter(COUNTER_FLOW_INSERT_FAILURE)?,
            flow_insert_failures,
        )?;
        expect_equal_u64(
            "control-bypass counter",
            fixture.read_counter(COUNTER_CONTROL_BYPASS)?,
            control_bypasses,
        )
    }

    /// Loads an ELF and seeds its maps for one isolated fixture.
    fn create_fixture(elf_path: &Path, config: &RuntimeConfigValue) -> RunnerResult<BpfFixture> {
        let mut fixture = BpfFixture::open(elf_path)?;
        fixture.seed_maps(config)?;
        Ok(fixture)
    }

    /// Verifies missing family targets pass through and increment target-miss.
    fn run_target_miss_fixture(elf_path: &Path) -> RunnerResult {
        let mut config = init_runtime_config();
        let ipv4_target = parse_ip("192.0.2.200")?;
        let client = parse_ip("2001:db8::10")?;
        let original_destination = parse_ip("2001:db8::20")?;
        set_ipv4_target(&mut config, &ipv4_target);

        let mut fixture = create_fixture(elf_path, &config)?;
        let mut input = PacketBuffer::default();
        build_ipv6_tcp_packet(
            &mut input,
            &client,
            &original_destination,
            40000,
            443,
            TCP_FLAG_SYN,
            100,
            0,
        );
        fixture.run_program("target-miss ingress", INGRESS_PROGRAM_NAME, &input, &input)?;
        assert_counter_values(&mut fixture, 1, 0, 0)?;
        assert_zero_counts(&mut fixture)
    }

    /// Verifies the first eligible packet creates flow state and indexes.
    fn run_flow_create_fixture(elf_path: &Path) -> RunnerResult {
        let mut config = init_runtime_config();
        let client = parse_ip("192.0.2.10")?;
        let original_destination = parse_ip("198.51.100.20")?;
        let target = parse_ip("203.0.113.30")?;
        set_ipv4_target(&mut config, &target);

        let mut fixture = create_fixture(elf_path, &config)?;
        let mut input = PacketBuffer::default();
        let mut expected = PacketBuffer::default();
        build_ipv4_tcp_packet(
            &mut input,
            &client,
            &original_destination,
            40000,
            443,
            TCP_FLAG_SYN,
            100,
            0,
        );
        build_ipv4_tcp_packet(
            &mut expected,
            &client,
            &target,
            40000,
            TARGET_PORT_V4,
            TCP_FLAG_SYN,
            100,
            0,
        );
        fixture.run_program(
            "flow-create ingress",
            INGRESS_PROGRAM_NAME,
            &input,
            &expected,
        )?;

        let original_key = make_tuple_key(&client, &original_destination, PROTOCOL_TCP, 40000, 443);
        let target_key = make_tuple_key(&client, &target, PROTOCOL_TCP, 40000, TARGET_PORT_V4);
        let reverse_key = make_tuple_key(&target, &client, PROTOCOL_TCP, TARGET_PORT_V4, 40000);
        let flow_id = tuple_hash(&original_key);
        let state_key = make_flow_state_key(flow_id, 1);

        assert_counter_values(&mut fixture, 0, 0, 0)?;
        expect_equal_u64(
            "flow-index count",
            fixture.count_flow_index_entries()? as u64,
            3,
        )?;
        expect_equal_u64(
            "flow-state count",
            fixture.count_flow_state_entries()? as u64,
            1,
        )?;
        expect_equal_u64("active-flow count", fixture.read_active_flows()?, 1)?;

        let index_value = fixture.lookup_flow_index(&original_key)?;
        expect_true("original index exists", index_value.is_some())?;
        expect_index_owner("original index owner", &index_value.unwrap(), flow_id, 1)?;

        let index_value = fixture.lookup_flow_index(&target_key)?;
        expect_true("target index exists", index_value.is_some())?;
        expect_index_owner("target index owner", &index_value.unwrap(), flow_id, 1)?;

        let index_value = fixture.lookup_flow_index(&reverse_key)?;
        expect_true("reverse index exists", index_value.is_some())?;
        expect_index_owner("reverse index owner", &index_value.unwrap(), flow_id, 1)?;

        let state_value = fixture.lookup_flow_state(&state_key)?;
        expect_true("flow state exists", state_value.is_some())?;
        let state_value = state_value.unwrap();
        expect_tuple_equal(
            "state original",
            &flow_state_tuple(&state_value, 0),
            &original_key,
        )?;
        expect_tuple_equal(
            "state target",
            &flow_state_tuple(&state_value, 40),
            &target_key,
        )?;
        expect_tuple_equal(
            "state reverse",
            &flow_state_tuple(&state_value, 80),
            &reverse_key,
        )?;
        expect_equal_u64("state flow_id", read_u64_ne(&state_value, 148), flow_id)?;
        expect_equal_u64("state generation", read_u32_ne(&state_value, 156) as u64, 1)?;
        expect_equal_u64(
            "state protocol flags",
            read_u32_ne(&state_value, 128) as u64,
            PROTOCOL_FLAG_TCP as u64,
        )?;
        expect_equal_u64(
            "state tcp flags",
            read_u32_ne(&state_value, 132) as u64,
            TCP_SYN_BIT as u64,
        )?;
        expect_equal_u64(
            "state lifecycle",
            state_value[138] as u64,
            FLOW_ACTIVE as u64,
        )?;
        expect_equal_u64("state fin-seen mask", state_value[136] as u64, 0)?;
        expect_equal_u64("state fin-ack mask", state_value[137] as u64, 0)?;
        expect_equal_u64("state terminal deadline", read_u64_ne(&state_value, 140), 0)?;
        expect_true(
            "state last_used_ns is nonzero",
            read_u64_ne(&state_value, 120) > 0,
        )
    }

    /// Verifies ingress destination/port rewriting and checksum updates.
    fn run_forward_rewrite_fixture(elf_path: &Path) -> RunnerResult {
        const PAYLOAD: &[u8] = b"SSP6";

        let mut config = init_runtime_config();
        let client = parse_ip("2001:db8::10")?;
        let original_destination = parse_ip("2001:db8::20")?;
        let target = parse_ip("2001:db8::30")?;
        set_ipv6_target(&mut config, &target);

        let mut fixture = create_fixture(elf_path, &config)?;
        let mut input = PacketBuffer::default();
        let mut expected = PacketBuffer::default();
        build_ipv6_udp_packet(
            &mut input,
            &client,
            &original_destination,
            40001,
            53,
            PAYLOAD,
        );
        build_ipv6_udp_packet(
            &mut expected,
            &client,
            &target,
            40001,
            TARGET_PORT_V6,
            PAYLOAD,
        );
        fixture.run_program(
            "forward-rewrite ingress",
            INGRESS_PROGRAM_NAME,
            &input,
            &expected,
        )?;

        let original_key = make_tuple_key(&client, &original_destination, PROTOCOL_UDP, 40001, 53);
        let target_key = make_tuple_key(&client, &target, PROTOCOL_UDP, 40001, TARGET_PORT_V6);
        let reverse_key = make_tuple_key(&target, &client, PROTOCOL_UDP, TARGET_PORT_V6, 40001);
        let flow_id = tuple_hash(&original_key);
        let state_key = make_flow_state_key(flow_id, 1);

        assert_counter_values(&mut fixture, 0, 0, 0)?;
        expect_equal_u64(
            "flow-index count",
            fixture.count_flow_index_entries()? as u64,
            3,
        )?;
        expect_equal_u64(
            "flow-state count",
            fixture.count_flow_state_entries()? as u64,
            1,
        )?;
        let state_value = fixture.lookup_flow_state(&state_key)?;
        expect_true("udp flow state exists", state_value.is_some())?;
        let state_value = state_value.unwrap();
        expect_tuple_equal(
            "udp state original",
            &flow_state_tuple(&state_value, 0),
            &original_key,
        )?;
        expect_tuple_equal(
            "udp state target",
            &flow_state_tuple(&state_value, 40),
            &target_key,
        )?;
        expect_tuple_equal(
            "udp state reverse",
            &flow_state_tuple(&state_value, 80),
            &reverse_key,
        )?;
        expect_equal_u64(
            "udp protocol flags",
            read_u32_ne(&state_value, 128) as u64,
            PROTOCOL_FLAG_UDP as u64,
        )?;
        expect_equal_u64("udp tcp flags", read_u32_ne(&state_value, 132) as u64, 0)?;
        expect_equal_u64("udp lifecycle", state_value[138] as u64, FLOW_ACTIVE as u64)?;
        expect_equal_u64("udp terminal deadline", read_u64_ne(&state_value, 140), 0)
    }

    /// Verifies egress reverse lookup restores the original destination tuple.
    fn run_reverse_rewrite_fixture(elf_path: &Path) -> RunnerResult {
        let mut config = init_runtime_config();
        let client = parse_ip("192.0.2.10")?;
        let original_destination = parse_ip("198.51.100.20")?;
        let target = parse_ip("203.0.113.30")?;
        set_ipv4_target(&mut config, &target);

        let mut fixture = create_fixture(elf_path, &config)?;
        let mut ingress_input = PacketBuffer::default();
        let mut ingress_expected = PacketBuffer::default();
        let mut egress_input = PacketBuffer::default();
        let mut egress_expected = PacketBuffer::default();

        build_ipv4_tcp_packet(
            &mut ingress_input,
            &client,
            &original_destination,
            40000,
            443,
            TCP_FLAG_SYN,
            100,
            0,
        );
        build_ipv4_tcp_packet(
            &mut ingress_expected,
            &client,
            &target,
            40000,
            TARGET_PORT_V4,
            TCP_FLAG_SYN,
            100,
            0,
        );
        fixture.run_program(
            "reverse-rewrite ingress",
            INGRESS_PROGRAM_NAME,
            &ingress_input,
            &ingress_expected,
        )?;

        build_ipv4_tcp_packet(
            &mut egress_input,
            &target,
            &client,
            TARGET_PORT_V4,
            40000,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
            200,
            101,
        );
        build_ipv4_tcp_packet(
            &mut egress_expected,
            &original_destination,
            &client,
            443,
            40000,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
            200,
            101,
        );
        fixture.run_program(
            "reverse-rewrite egress",
            EGRESS_PROGRAM_NAME,
            &egress_input,
            &egress_expected,
        )?;

        let original_key = make_tuple_key(&client, &original_destination, PROTOCOL_TCP, 40000, 443);
        let flow_id = tuple_hash(&original_key);
        let state_key = make_flow_state_key(flow_id, 1);
        let state_value = fixture.lookup_flow_state(&state_key)?;
        expect_true("reverse flow state exists", state_value.is_some())?;
        let state_value = state_value.unwrap();
        expect_equal_u64(
            "reverse tcp flags",
            read_u32_ne(&state_value, 132) as u64,
            (TCP_SYN_BIT | TCP_SYN_ACK_BIT) as u64,
        )?;
        expect_equal_u64(
            "reverse flow lifecycle",
            state_value[138] as u64,
            FLOW_ACTIVE as u64,
        )
    }

    /// Verifies packets to the control listener bypass flow rewriting.
    fn run_control_bypass_fixture(elf_path: &Path) -> RunnerResult {
        const PAYLOAD: &[u8] = b"SSP4";

        let mut config = init_runtime_config();
        let client = parse_ip("192.0.2.10")?;
        let listener_destination = parse_ip("198.51.100.250")?;
        let target = parse_ip("203.0.113.30")?;
        set_ipv4_target(&mut config, &target);

        let mut fixture = create_fixture(elf_path, &config)?;
        let mut tcp_input = PacketBuffer::default();
        let mut udp_input = PacketBuffer::default();
        let mut udp_expected = PacketBuffer::default();

        build_ipv4_tcp_packet(
            &mut tcp_input,
            &client,
            &listener_destination,
            40002,
            LISTENER_PORT,
            TCP_FLAG_SYN,
            10,
            0,
        );
        fixture.run_program(
            "control-bypass tcp ingress",
            INGRESS_PROGRAM_NAME,
            &tcp_input,
            &tcp_input,
        )?;
        assert_counter_values(&mut fixture, 0, 0, 1)?;
        assert_zero_counts(&mut fixture)?;

        build_ipv4_udp_packet(
            &mut udp_input,
            &client,
            &listener_destination,
            40003,
            LISTENER_PORT,
            PAYLOAD,
        );
        build_ipv4_udp_packet(
            &mut udp_expected,
            &client,
            &target,
            40003,
            TARGET_PORT_V4,
            PAYLOAD,
        );
        fixture.run_program(
            "control-bypass udp ingress",
            INGRESS_PROGRAM_NAME,
            &udp_input,
            &udp_expected,
        )?;
        assert_counter_values(&mut fixture, 0, 0, 1)?;
        expect_equal_u64(
            "udp flow-index count",
            fixture.count_flow_index_entries()? as u64,
            3,
        )?;
        expect_equal_u64(
            "udp flow-state count",
            fixture.count_flow_state_entries()? as u64,
            1,
        )?;
        expect_equal_u64("udp active-flow count", fixture.read_active_flows()?, 1)
    }

    /// Verifies both FIN/ACK directions schedule terminal flow cleanup.
    fn run_fin_ack_teardown_fixture(elf_path: &Path) -> RunnerResult {
        let mut config = init_runtime_config();
        let client = parse_ip("192.0.2.10")?;
        let original_destination = parse_ip("198.51.100.20")?;
        let target = parse_ip("203.0.113.30")?;
        set_ipv4_target(&mut config, &target);

        let mut fixture = create_fixture(elf_path, &config)?;
        let mut packet_in = PacketBuffer::default();
        let mut packet_expected = PacketBuffer::default();

        build_ipv4_tcp_packet(
            &mut packet_in,
            &client,
            &original_destination,
            40004,
            443,
            TCP_FLAG_SYN,
            100,
            0,
        );
        build_ipv4_tcp_packet(
            &mut packet_expected,
            &client,
            &target,
            40004,
            TARGET_PORT_V4,
            TCP_FLAG_SYN,
            100,
            0,
        );
        fixture.run_program(
            "fin-ack ingress syn",
            INGRESS_PROGRAM_NAME,
            &packet_in,
            &packet_expected,
        )?;

        build_ipv4_tcp_packet(
            &mut packet_in,
            &target,
            &client,
            TARGET_PORT_V4,
            40004,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
            200,
            101,
        );
        build_ipv4_tcp_packet(
            &mut packet_expected,
            &original_destination,
            &client,
            443,
            40004,
            TCP_FLAG_SYN | TCP_FLAG_ACK,
            200,
            101,
        );
        fixture.run_program(
            "fin-ack egress syn-ack",
            EGRESS_PROGRAM_NAME,
            &packet_in,
            &packet_expected,
        )?;

        build_ipv4_tcp_packet(
            &mut packet_in,
            &client,
            &original_destination,
            40004,
            443,
            TCP_FLAG_FIN,
            101,
            201,
        );
        build_ipv4_tcp_packet(
            &mut packet_expected,
            &client,
            &target,
            40004,
            TARGET_PORT_V4,
            TCP_FLAG_FIN,
            101,
            201,
        );
        fixture.run_program(
            "fin-ack ingress fin",
            INGRESS_PROGRAM_NAME,
            &packet_in,
            &packet_expected,
        )?;

        build_ipv4_tcp_packet(
            &mut packet_in,
            &target,
            &client,
            TARGET_PORT_V4,
            40004,
            TCP_FLAG_FIN | TCP_FLAG_ACK,
            201,
            102,
        );
        build_ipv4_tcp_packet(
            &mut packet_expected,
            &original_destination,
            &client,
            443,
            40004,
            TCP_FLAG_FIN | TCP_FLAG_ACK,
            201,
            102,
        );
        fixture.run_program(
            "fin-ack egress fin-ack",
            EGRESS_PROGRAM_NAME,
            &packet_in,
            &packet_expected,
        )?;

        build_ipv4_tcp_packet(
            &mut packet_in,
            &client,
            &original_destination,
            40004,
            443,
            TCP_FLAG_ACK,
            102,
            202,
        );
        build_ipv4_tcp_packet(
            &mut packet_expected,
            &client,
            &target,
            40004,
            TARGET_PORT_V4,
            TCP_FLAG_ACK,
            102,
            202,
        );
        fixture.run_program(
            "fin-ack ingress ack",
            INGRESS_PROGRAM_NAME,
            &packet_in,
            &packet_expected,
        )?;

        let original_key = make_tuple_key(&client, &original_destination, PROTOCOL_TCP, 40004, 443);
        let flow_id = tuple_hash(&original_key);
        let state_key = make_flow_state_key(flow_id, 1);
        let state_value = fixture.lookup_flow_state(&state_key)?;
        expect_true("fin-ack flow state exists", state_value.is_some())?;
        let state_value = state_value.unwrap();
        let tcp_flags = read_u32_ne(&state_value, 132);
        let last_used_ns = read_u64_ne(&state_value, 120);
        let terminal_deadline_ns = read_u64_ne(&state_value, 140);
        expect_equal_u64(
            "fin-ack tcp flags",
            tcp_flags as u64,
            (TCP_SYN_BIT | TCP_SYN_ACK_BIT | TCP_ACK_BIT | TCP_FIN_BIT) as u64,
        )?;
        expect_equal_u64("fin-ack fin-seen mask", state_value[136] as u64, 0x3)?;
        expect_equal_u64("fin-ack fin-ack mask", state_value[137] as u64, 0x3)?;
        expect_true(
            "fin-ack terminal deadline is set",
            terminal_deadline_ns > last_used_ns,
        )
    }

    /// Verifies a TCP RST marks the flow removable immediately.
    fn run_rst_fixture(elf_path: &Path) -> RunnerResult {
        let mut config = init_runtime_config();
        let client = parse_ip("192.0.2.10")?;
        let original_destination = parse_ip("198.51.100.20")?;
        let target = parse_ip("203.0.113.30")?;
        set_ipv4_target(&mut config, &target);

        let mut fixture = create_fixture(elf_path, &config)?;
        let mut ingress_input = PacketBuffer::default();
        let mut ingress_expected = PacketBuffer::default();
        let mut egress_input = PacketBuffer::default();
        let mut egress_expected = PacketBuffer::default();

        build_ipv4_tcp_packet(
            &mut ingress_input,
            &client,
            &original_destination,
            40005,
            443,
            TCP_FLAG_SYN,
            100,
            0,
        );
        build_ipv4_tcp_packet(
            &mut ingress_expected,
            &client,
            &target,
            40005,
            TARGET_PORT_V4,
            TCP_FLAG_SYN,
            100,
            0,
        );
        fixture.run_program(
            "rst ingress",
            INGRESS_PROGRAM_NAME,
            &ingress_input,
            &ingress_expected,
        )?;

        build_ipv4_tcp_packet(
            &mut egress_input,
            &target,
            &client,
            TARGET_PORT_V4,
            40005,
            TCP_FLAG_RST | TCP_FLAG_ACK,
            200,
            101,
        );
        build_ipv4_tcp_packet(
            &mut egress_expected,
            &original_destination,
            &client,
            443,
            40005,
            TCP_FLAG_RST | TCP_FLAG_ACK,
            200,
            101,
        );
        fixture.run_program(
            "rst egress",
            EGRESS_PROGRAM_NAME,
            &egress_input,
            &egress_expected,
        )?;
        assert_counter_values(&mut fixture, 0, 0, 0)?;
        assert_zero_counts(&mut fixture)
    }

    /// Resolves a stable fixture name from the registry.
    fn find_fixture(name: &str) -> Option<&'static FixtureDef> {
        FIXTURES.iter().find(|fixture| fixture.name == name)
    }
}

#[cfg(target_os = "linux")]
/// Selects and executes the Linux fixture runner, returning its exit status.
fn main() -> std::process::ExitCode {
    linux::main()
}
