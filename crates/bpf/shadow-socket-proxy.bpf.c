// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

/**
 * @file
 * @brief TC BPF packet rewriting and per-flow redirection state.
 *
 * The ingress classifier creates or resolves a flow and rewrites the
 * destination tuple toward the configured host listener. The egress
 * classifier resolves the reverse tuple and restores the original
 * destination. IPv4 addresses are represented as IPv4-mapped 16-byte
 * addresses so the map ABI is shared with IPv6. Every packet access is
 * bounds-checked for the verifier, and L3/L4 checksums are updated whenever
 * an address or port changes. Unsupported protocols, fragments, malformed
 * packets, and control-service traffic pass through unchanged.
 */

/*
 * Build with a Linux clang toolchain and the kernel UAPI headers:
 *
 *   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
 *     -I/usr/include/$(uname -m)-linux-gnu -c shadow-socket-proxy.bpf.c \
 *     -o shadow-socket-proxy.bpf.o
 *
 * The program intentionally handles only Ethernet IPv4/IPv6 TCP/UDP first
 * fragments. Everything else returns TC_ACT_OK without touching the packet.
 */

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ipv6.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdbool.h>

#ifndef SEC
/** Places a classifier in the requested ELF section when libbpf headers are absent. */
#define SEC(name) __attribute__((section(name), used))
#endif

#ifndef __always_inline
/** Forces small packet-path helpers to inline for verifier-friendly control flow. */
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef bpf_htons
/** Compile-time host-to-network conversion used by the portable fixture build. */
#define bpf_htons(x) (__builtin_bswap16((__u16)(x)))
/** Compile-time network-to-host conversion used by the portable fixture build. */
#define bpf_ntohs(x) (__builtin_bswap16((__u16)(x)))
#endif

#ifndef __uint
/** Declares a map metadata field in the portable fallback ABI. */
#define __uint(name, value) int (*name)[value]
/** Declares a typed map metadata field in the portable fallback ABI. */
#define __type(name, value) typeof(value) *name
#endif

/** Looks up a key in a BPF map; NULL means no flow/config entry exists. */
static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
    (void *)BPF_FUNC_map_lookup_elem;
/** Inserts or replaces a map value while packet processing is in progress. */
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value,
                                   __u64 flags) =
    (void *)BPF_FUNC_map_update_elem;
/** Removes a map entry during flow teardown. */
static long (*bpf_map_delete_elem)(void *map, const void *key) =
    (void *)BPF_FUNC_map_delete_elem;
/** Supplies the monotonic nanosecond clock used for flow aging. */
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
/** Reads packet bytes with verifier-checked bounds handling. */
static long (*bpf_skb_load_bytes)(const struct __sk_buff *skb, __u32 offset,
                                  void *to, __u32 len) =
    (void *)BPF_FUNC_skb_load_bytes;
/** Writes packet bytes and optionally invalidates checksum state. */
static long (*bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset,
                                   const void *from, __u32 len, __u64 flags) =
    (void *)BPF_FUNC_skb_store_bytes;
/** Incrementally fixes the IPv4 header checksum after address changes. */
static long (*bpf_l3_csum_replace)(struct __sk_buff *skb, __u32 offset,
                                   __u64 from, __u64 to, __u64 size) =
    (void *)BPF_FUNC_l3_csum_replace;
/** Incrementally fixes TCP/UDP checksums after address or port changes. */
static long (*bpf_l4_csum_replace)(struct __sk_buff *skb, __u32 offset,
                                   __u64 from, __u64 to, __u64 flags) =
    (void *)BPF_FUNC_l4_csum_replace;
/** Computes a one-complement difference for IPv6 pseudo-header updates. */
static __s64 (*bpf_csum_diff)(__be32 *from, __u32 from_size, __be32 *to,
                              __u32 to_size, __wsum seed) =
    (void *)BPF_FUNC_csum_diff;

/** Version encoded in tuple/index/state map records. */
#define MAP_ABI_VERSION 1
/** ABI size of a tuple-index value. */
#define FLOW_INDEX_VALUE_LEN 16
/** ABI size of a flow-state key. */
#define FLOW_STATE_KEY_LEN 16
/** ABI size of a flow-state value including reserved padding. */
#define FLOW_STATE_VALUE_LEN 256
/** Maximum tuple indexes compiled into the ELF. */
#define FLOW_INDEX_MAX_ENTRIES 16384
/** Maximum native flow states compiled into the ELF. */
#define FLOW_STATE_MAX_ENTRIES 8192
/** Version of the runtime configuration map layout. */
#define RUNTIME_CONFIG_ABI_VERSION 3

/** Lifecycle value for a flow reserved before activation. */
#define FLOW_CREATING 1
/** Lifecycle value for a flow eligible for normal rewriting. */
#define FLOW_ACTIVE 2
/** Internal bit recording a client-to-target SYN. */
#define TCP_SYN_BIT (1U << 0)
/** Internal bit recording a target-to-client SYN/ACK. */
#define TCP_SYN_ACK_BIT (1U << 1)
/** Internal bit recording acknowledgement of a peer FIN. */
#define TCP_ACK_BIT (1U << 2)
/** Internal bit recording FIN in either direction. */
#define TCP_FIN_BIT (1U << 3)
/** Internal bit recording an immediate TCP reset. */
#define TCP_RST_BIT (1U << 4)
/** TCP wire FIN flag value. */
#define TCP_FLAG_FIN 0x01
/** TCP wire SYN flag value. */
#define TCP_FLAG_SYN 0x02
/** TCP wire RST flag value. */
#define TCP_FLAG_RST 0x04
/** TCP wire ACK flag value. */
#define TCP_FLAG_ACK 0x10

/** Packed tuple key shared by the three tuple-index entries for a flow. */
struct tuple_key {
/** Map ABI version in network byte order. */
    __be16 version;
/** Address family discriminator: 4 for IPv4, 6 for IPv6. */
    __u8 family;
/** TCP or UDP IP protocol number. */
    __u8 protocol;
/** Source address, IPv4-mapped when family is 4. */
    __u8 source[16];
/** Destination address, IPv4-mapped when family is 4. */
    __u8 destination[16];
/** Source transport port in network byte order. */
    __be16 source_port;
/** Destination transport port in network byte order. */
    __be16 destination_port;
} __attribute__((packed));

/** Packed tuple-index value that identifies a flow state record. */
struct flow_index_value {
/** Map ABI version in network byte order. */
    __be16 version;
/** Reserved zero bytes preserving the fixed ABI layout. */
    __u16 reserved;
/** Native flow-state identifier. */
    __u64 flow_id;
/** Generation paired with flow_id to reject stale indexes. */
    __u32 generation;
} __attribute__((packed));

/** Packed key for the native flow-state map. */
struct flow_state_key {
/** Map ABI version in network byte order. */
    __be16 version;
/** Reserved zero bytes preserving the fixed ABI layout. */
    __u16 reserved;
/** Native flow-state identifier addressed by this key. */
    __u64 flow_id;
/** Generation paired with flow_id. */
    __u32 generation;
} __attribute__((packed));

/** Packed bidirectional tuples and lifecycle data for one flow. */
struct flow_state_value {
/** Ingress tuple captured before destination rewriting. */
    struct tuple_key original;
/** Tuple sent toward the configured host listener. */
    struct tuple_key target;
/** Reply tuple used to restore the original destination. */
    struct tuple_key reverse;
/** Monotonic timestamp used for idle expiration. */
    __u64 last_used_ns;
/** Protocol bits accumulated for the flow. */
    __u32 protocol_flags;
/** TCP handshake and terminal-event bits. */
    __u32 tcp_state_flags;
/** One bit per direction after FIN is observed. */
    __u8 fin_seen_mask;
/** One bit per direction after the peer FIN is acknowledged. */
    __u8 fin_ack_seen_mask;
/** FLOW_CREATING or FLOW_ACTIVE lifecycle value. */
    __u8 lifecycle;
/** Reserved byte kept zero for ABI compatibility. */
    __u8 reserved;
/** Deletion deadline after both FIN exchanges; zero while non-terminal. */
    __u64 terminal_deadline_ns;
/** Identifier shared by all tuple indexes. */
    __u64 flow_id;
/** Generation shared by all tuple indexes. */
    __u32 generation;
/** Reserved tail keeping the state value at 256 bytes. */
    __u8 padding[96];
} __attribute__((packed));

/** Single packet-path counter value. */
struct counter_value {
/** Monotonic packet-path count for one counter slot. */
    __u64 value;
};

/** Packed targets, listener identity, and timeout settings read by classifiers. */
struct runtime_config_value {
/** Runtime configuration ABI version in network byte order. */
    __be16 schema_version;
/** Non-zero when the IPv4 rewrite target is usable. */
    __u8 v4_target_set;
/** Non-zero when the IPv6 rewrite target is usable. */
    __u8 v6_target_set;
/** IPv4 target address in mapped 16-byte form. */
    __u8 v4_target[4];
/** IPv4 target port in network byte order. */
    __be16 v4_target_port;
/** IPv6 target address. */
    __u8 v6_target[16];
/** IPv6 target port in network byte order. */
    __be16 v6_target_port;
/** Control listener family discriminator. */
    __u8 listener_family;
/** Wildcard bits used to bypass listener-bound control traffic. */
    __u8 listener_wildcard_flags;
/** Control listener address in the shared 16-byte representation. */
    __u8 listener_address[16];
/** Control listener port in network byte order. */
    __be16 listener_port;
/** Idle lifetime in monotonic nanoseconds. */
    __u64 idle_ttl_ns;
/** TCP terminal grace in monotonic nanoseconds. */
    __u64 terminal_grace_ns;
/** Maximum active-flow slots the classifier may reserve. */
    __u32 active_flow_capacity;
/** Reserved tail preserving the 80-byte map value layout. */
    __u8 padding[12];
} __attribute__((packed));

/** Verifier-checked offsets and normalized tuple fields for one packet. */
struct packet_info {
/** Offset of the IPv4/IPv6 header from the packet start. */
    __u32 l3_offset;
/** Offset of the TCP/UDP header from the packet start. */
    __u32 l4_offset;
/** Offset of the transport checksum field. */
    __u32 l4_checksum_offset;
/** Parsed address family discriminator. */
    __u8 family;
/** Parsed TCP or UDP protocol number. */
    __u8 protocol;
/** Parsed TCP flags; zero for UDP. */
    __u8 tcp_flags;
/** Parsed source address in normalized ABI form. */
    __u8 source[16];
/** Parsed destination address in normalized ABI form. */
    __u8 destination[16];
/** Parsed source transport port. */
    __be16 source_port;
/** Parsed destination transport port. */
    __be16 destination_port;
};

/** Maps original/target/reverse tuple keys to flow id and generation. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLOW_INDEX_MAX_ENTRIES);
    __type(key, struct tuple_key);
    __type(value, struct flow_index_value);
} ssp_flow_index_v1 SEC(".maps");

/** Stores one complete state record per active flow. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLOW_STATE_MAX_ENTRIES);
    __type(key, struct flow_state_key);
    __type(value, struct flow_state_value);
} ssp_flow_state_v1 SEC(".maps");

/** Array of target-miss, insert-failure, and control-bypass counters. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, struct counter_value);
} ssp_tc_counters_v1 SEC(".maps");

/** Single-entry map containing validated runtime targets and limits. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct runtime_config_value);
} ssp_runtime_config_v3 SEC(".maps");

/** Per-CPU scratch storage for verifier-safe packet processing. */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct flow_state_value);
} ssp_tc_scratch_v1 SEC(".maps");

/** Array used to reserve and release bounded active-flow slots. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ssp_tc_active_flows_v1 SEC(".maps");

/**
 * Copies exactly four bytes without relying on unbounded packet pointers.
 * @param to destination buffer with four writable bytes
 * @param from source buffer with four readable bytes
 */
static __always_inline void copy4(__u8 *to, const __u8 *from)
{
    to[0] = from[0];
    to[1] = from[1];
    to[2] = from[2];
    to[3] = from[3];
}

/**
 * Copies one normalized 16-byte address without loops the verifier cannot prove.
 * @param to destination address buffer
 * @param from source address buffer
 */
static __always_inline void copy16(__u8 *to, const __u8 *from)
{
    __u32 i;
    for (i = 0; i < 16; i++)
        to[i] = from[i];
}

/**
 * Clears a normalized 16-byte address buffer.
 * @param value address buffer to zero
 */
static __always_inline void clear16(__u8 *value)
{
    __u32 i;
    for (i = 0; i < 16; i++)
        value[i] = 0;
}

/**
 * Converts an IPv4 address to the ABI's IPv4-mapped 16-byte form.
 * @param to destination 16-byte ABI address
 * @param from four-byte IPv4 address
 */
static __always_inline void ipv4_to_mapped(__u8 *to, const __u8 *from)
{
    __u32 i;
    for (i = 0; i < 10; i++)
        to[i] = 0;
    to[10] = 0xff;
    to[11] = 0xff;
    for (i = 0; i < 4; i++)
        to[12 + i] = from[i];
}

/**
 * Increments one bounded counter-map slot when the index exists.
 * Missing slots are ignored because counters must not affect packet verdicts.
 * @param index counter slot (0 target miss, 1 insert failure, 2 control bypass)
 */
static __always_inline void increment_counter(__u32 index)
{
    struct counter_value *counter = bpf_map_lookup_elem(&ssp_tc_counters_v1, &index);
    __u64 current;
    int attempt;

    if (!counter)
        return;
    #pragma unroll
    for (attempt = 0; attempt < 8; attempt++) {
        current = __sync_fetch_and_add(&counter->value, 0);
        if (current == ~0ULL ||
            __sync_bool_compare_and_swap(&counter->value, current, current + 1))
            return;
    }
}

/**
 * Reserves one active-flow slot, returning failure when capacity is exhausted.
 * The increment is rolled back when the configured capacity has been reached.
 * @return 1 when a slot is reserved, otherwise 0
 */
static __always_inline int reserve_flow_slot(void)
{
    __u32 config_key = 0;
    __u64 *count = bpf_map_lookup_elem(&ssp_tc_active_flows_v1, &config_key);
    struct runtime_config_value *config =
        bpf_map_lookup_elem(&ssp_runtime_config_v3, &config_key);
    __u64 previous;

    if (!count)
        return 0;
    previous = __sync_fetch_and_add(count, 1);
    if (config && config->active_flow_capacity &&
        previous >= config->active_flow_capacity) {
        __sync_fetch_and_sub(count, 1);
        return 0;
    }
    return 1;
}

/**
 * Releases a previously reserved active-flow slot without underflowing the
 * shared count.
 */
static __always_inline void release_flow_slot(void)
{
    __u32 config_key = 0;
    __u64 *count = bpf_map_lookup_elem(&ssp_tc_active_flows_v1, &config_key);
    __u64 current;
    int attempt;

    if (!count)
        return;
    for (attempt = 0; attempt < 8; attempt++) {
        current = __sync_fetch_and_add(count, 0);
        if (!current)
            return;
        if (__sync_bool_compare_and_swap(count, current, current - 1))
            return;
    }
}

/**
 * Parses the first Ethernet/IP/TCP or UDP headers after verifier bounds
 * checks and normalizes the tuple into `packet`.
 * Only unfragmented Ethernet IPv4/IPv6 TCP/UDP packets are accepted.
 * @param skb packet currently classified by TC
 * @param packet output offsets, addresses, ports, and flags
 * @return 1 for a supported well-formed packet, otherwise 0
 */
static __always_inline int parse_packet(struct __sk_buff *skb, struct packet_info *packet)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr *eth = data;
    __u16 protocol;
    __u32 ip_header_len;
    __u16 fragment;
    void *l4;

    if ((void *)(eth + 1) > data_end)
        return 0;
    protocol = eth->h_proto;
    if (protocol != bpf_htons(ETH_P_IP) && protocol != bpf_htons(ETH_P_IPV6))
        return 0;

    if (protocol == bpf_htons(ETH_P_IP)) {
        struct iphdr *ip = data + sizeof(*eth);
        if ((void *)(ip + 1) > data_end || ip->ihl < 5)
            return 0;
        ip_header_len = ip->ihl * 4;
        if (data + sizeof(*eth) + ip_header_len > data_end)
            return 0;
        fragment = bpf_ntohs(ip->frag_off);
        if ((fragment & 0x1fff) != 0)
            return 0;
        if (bpf_ntohs(ip->tot_len) < ip_header_len + 8)
            return 0;
        packet->family = 4;
        packet->protocol = ip->protocol;
        packet->l3_offset = sizeof(*eth);
        packet->l4_offset = sizeof(*eth) + ip_header_len;
        l4 = (void *)ip + ip_header_len;
        clear16(packet->source);
        clear16(packet->destination);
        ipv4_to_mapped(packet->source, (__u8 *)&ip->saddr);
        ipv4_to_mapped(packet->destination, (__u8 *)&ip->daddr);
    } else {
        struct ipv6hdr *ip6 = data + sizeof(*eth);
        if ((void *)(ip6 + 1) > data_end)
            return 0;
        if (ip6->nexthdr != IPPROTO_TCP && ip6->nexthdr != IPPROTO_UDP)
            return 0;
        packet->family = 6;
        packet->protocol = ip6->nexthdr;
        packet->l3_offset = sizeof(*eth);
        packet->l4_offset = sizeof(*eth) + sizeof(*ip6);
        l4 = (void *)(ip6 + 1);
        copy16(packet->source, (__u8 *)&ip6->saddr);
        copy16(packet->destination, (__u8 *)&ip6->daddr);
    }

    if (packet->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = l4;
        __u32 tcp_header_len;
        if ((void *)(tcp + 1) > data_end)
            return 0;
        tcp_header_len = tcp->doff * 4;
        if (tcp->doff < 5 || data + packet->l4_offset + tcp_header_len > data_end)
            return 0;
        packet->source_port = tcp->source;
        packet->destination_port = tcp->dest;
        packet->tcp_flags = ((__u8 *)tcp)[13];
        packet->l4_checksum_offset = packet->l4_offset + 16;
    } else if (packet->protocol == IPPROTO_UDP) {
        struct udphdr *udp = l4;
        if ((void *)(udp + 1) > data_end || bpf_ntohs(udp->len) < sizeof(*udp))
            return 0;
        packet->source_port = udp->source;
        packet->destination_port = udp->dest;
        packet->l4_checksum_offset = packet->l4_offset + 6;
    } else {
        return 0;
    }
    return 1;
}

/**
 * Builds the packed map key from normalized packet tuple fields.
 * @param key output packed ABI key
 * @param packet parsed family and protocol
 * @param source normalized source address
 * @param destination normalized destination address
 * @param source_port source port in network byte order
 * @param destination_port destination port in network byte order
 */
static __always_inline void make_tuple_key(struct tuple_key *key,
                                           const struct packet_info *packet,
                                           const __u8 *source,
                                           const __u8 *destination,
                                           __be16 source_port,
                                           __be16 destination_port)
{
    __u32 i;
    key->version = bpf_htons(MAP_ABI_VERSION);
    key->family = packet->family;
    key->protocol = packet->protocol;
    for (i = 0; i < 16; i++) {
        key->source[i] = source[i];
        key->destination[i] = destination[i];
    }
    key->source_port = source_port;
    key->destination_port = destination_port;
}

/**
 * Hashes a tuple key with FNV-1a; the non-zero result is used as a flow id.
 * @param key packed tuple to hash
 * @return non-zero deterministic flow id candidate
 */
static __always_inline __u64 tuple_hash(const struct tuple_key *key)
{
    const __u8 *bytes = (const __u8 *)key;
    __u64 hash = 1469598103934665603ULL;
    __u32 i;
    for (i = 0; i < sizeof(*key); i++)
        hash = (hash ^ bytes[i]) * 1099511628211ULL;
    if (hash == 0)
        hash = 1;
    return hash;
}

/**
 * Updates the TCP or UDP checksum for an address and port substitution.
 * IPv4 uses a four-byte incremental update; IPv6 uses the checksum-diff
 * helper for the complete pseudo-header address.
 * @param skb packet whose transport checksum is updated
 * @param packet parsed family and checksum offset
 * @param old_address address currently represented in the pseudo-header
 * @param new_address replacement pseudo-header address
 * @param old_port transport port currently in the packet
 * @param new_port replacement transport port
 * @return zero after issuing the checksum helper updates
 */
static __always_inline int update_l4_checksum(struct __sk_buff *skb,
                                              const struct packet_info *packet,
                                              const __u8 *old_address,
                                              const __u8 *new_address,
                                              __be16 old_port,
                                              __be16 new_port)
{
    if (packet->family == 4) {
        __u32 old4;
        __u32 new4;
        __builtin_memcpy(&old4, old_address + 12, sizeof(old4));
        __builtin_memcpy(&new4, new_address + 12, sizeof(new4));
        bpf_l4_csum_replace(skb, packet->l4_checksum_offset, old4, new4, 4);
    } else {
        __s64 diff = bpf_csum_diff((__be32 *)old_address, 16,
                                   (__be32 *)new_address, 16, 0);
        bpf_l4_csum_replace(skb, packet->l4_checksum_offset, 0, diff,
                            BPF_F_PSEUDO_HDR | 4);
    }
    bpf_l4_csum_replace(skb, packet->l4_checksum_offset, old_port, new_port, 2);
    return 0;
}

/**
 * Rewrites an ingress packet destination toward the configured host listener
 * and updates both network- and transport-layer checksums.
 * @param skb packet to mutate
 * @param packet parsed packet offsets and original destination tuple
 * @param new_address configured target address
 * @param new_port configured target port
 * @return zero after the address and port stores are issued
 */
static __always_inline int rewrite_destination(struct __sk_buff *skb,
                                               const struct packet_info *packet,
                                               const __u8 *new_address,
                                               __be16 new_port)
{
    if (packet->family == 4) {
        __u32 old4;
        __u32 new4;
        __builtin_memcpy(&old4, packet->destination + 12, sizeof(old4));
        __builtin_memcpy(&new4, new_address + 12, sizeof(new4));
        bpf_l3_csum_replace(skb, packet->l3_offset + 10, old4, new4, 4);
        bpf_skb_store_bytes(skb, packet->l3_offset + 16, new_address + 12, 4, 0);
    } else {
        bpf_skb_store_bytes(skb, packet->l3_offset + 24, new_address, 16, 0);
    }
    update_l4_checksum(skb, packet, packet->destination, new_address,
                       packet->destination_port, new_port);
    bpf_skb_store_bytes(skb, packet->l4_offset + 2, &new_port, sizeof(new_port), 0);
    return 0;
}

/**
 * Rewrites an egress packet source to the original destination tuple and
 * updates both network- and transport-layer checksums.
 * @param skb packet to mutate
 * @param packet parsed packet offsets and current source tuple
 * @param new_address original destination address to restore
 * @param new_port original destination port to restore
 * @return zero after the address and port stores are issued
 */
static __always_inline int rewrite_source(struct __sk_buff *skb,
                                           const struct packet_info *packet,
                                           const __u8 *new_address,
                                           __be16 new_port)
{
    if (packet->family == 4) {
        __u32 old4;
        __u32 new4;
        __builtin_memcpy(&old4, packet->source + 12, sizeof(old4));
        __builtin_memcpy(&new4, new_address + 12, sizeof(new4));
        bpf_l3_csum_replace(skb, packet->l3_offset + 10, old4, new4, 4);
        bpf_skb_store_bytes(skb, packet->l3_offset + 12, new_address + 12, 4, 0);
    } else {
        bpf_skb_store_bytes(skb, packet->l3_offset + 8, new_address, 16, 0);
    }
    update_l4_checksum(skb, packet, packet->source, new_address,
                       packet->source_port, new_port);
    bpf_skb_store_bytes(skb, packet->l4_offset, &new_port, sizeof(new_port), 0);
    return 0;
}

/**
 * Selects the configured IPv4 or IPv6 target and writes its port.
 * Disabled, zero, unspecified, or schema-mismatched targets are rejected.
 * @param packet parsed family selecting the target field
 * @param target output normalized target address
 * @param target_port output target port in network byte order
 * @return 1 when a usable family target exists, otherwise 0
 */
static __always_inline int target_for_packet(const struct packet_info *packet,
                                             __u8 *target,
                                             __be16 *target_port)
{
    __u32 config_key = 0;
    __u32 i;
    __u8 nonzero;
    struct runtime_config_value *config =
        bpf_map_lookup_elem(&ssp_runtime_config_v3, &config_key);

    if (!config ||
        bpf_ntohs(config->schema_version) != RUNTIME_CONFIG_ABI_VERSION)
        return 0;
    if (packet->family == 4) {
        if (config->v4_target_set != 1 ||
            bpf_ntohs(config->v4_target_port) == 0)
            return 0;
        nonzero = 0;
        for (i = 0; i < 4; i++)
            nonzero |= config->v4_target[i];
        if (!nonzero)
            return 0;
        clear16(target);
        ipv4_to_mapped(target, config->v4_target);
        *target_port = config->v4_target_port;
        return 1;
    }
    if (config->v6_target_set != 1 ||
        bpf_ntohs(config->v6_target_port) == 0)
        return 0;
    nonzero = 0;
    for (i = 0; i < 16; i++)
        nonzero |= config->v6_target[i];
    if (!nonzero)
        return 0;
    copy16(target, config->v6_target);
    *target_port = config->v6_target_port;
    return 1;
}

/**
 * Returns true when the packet targets the configured control listener.
 * Wildcard listeners match any address in their family; only TCP is bypassed.
 * @param packet parsed packet tuple
 * @param ingress choose destination matching for ingress or source matching
 *        for egress
 * @return 1 for control traffic that must not create or rewrite a flow
 */
static __always_inline int is_control_packet(const struct packet_info *packet,
                                             bool ingress)
{
    __u32 config_key = 0;
    struct runtime_config_value *config =
        bpf_map_lookup_elem(&ssp_runtime_config_v3, &config_key);
    const __u8 *endpoint = ingress ? packet->destination : packet->source;
    __be16 port = ingress ? packet->destination_port : packet->source_port;
    __u32 i;

    if (!config ||
        bpf_ntohs(config->schema_version) != RUNTIME_CONFIG_ABI_VERSION ||
        packet->protocol != IPPROTO_TCP ||
        port != config->listener_port)
        return 0;
    if (packet->family == 4) {
        if (config->listener_family != 4)
            return 0;
        if (config->listener_wildcard_flags & 1)
            return 1;
        for (i = 0; i < 4; i++)
            if (endpoint[12 + i] != config->listener_address[12 + i])
                return 0;
        return 1;
    }
    if (config->listener_family != 6)
        return 0;
    if (config->listener_wildcard_flags & 2)
        return 1;
    for (i = 0; i < 16; i++)
        if (endpoint[i] != config->listener_address[i])
            return 0;
    return 1;
}

/**
 * Updates directional SYN/FIN/ACK/RST state and terminal deadline.
 * @param state flow record mutated in place
 * @param direction zero for original-to-target, one for reverse traffic
 * @param flags wire TCP flags from the current packet
 * @param now monotonic timestamp used for last-use and terminal deadline
 */
static __always_inline void update_tcp_state(struct flow_state_value *state,
                                             __u8 direction,
                                             __u8 flags,
                                             __u64 now)
{
    __u32 config_key = 0;
    struct runtime_config_value *config =
        bpf_map_lookup_elem(&ssp_runtime_config_v3, &config_key);
    __u64 grace = config && config->terminal_grace_ns
                      ? config->terminal_grace_ns
                      : 30ULL * 1000ULL * 1000ULL * 1000ULL;
    if (state->protocol_flags != 1)
        return;
    state->last_used_ns = now;
    if (flags & TCP_FLAG_SYN)
        state->tcp_state_flags |= direction ? TCP_SYN_ACK_BIT : TCP_SYN_BIT;
    if ((flags & TCP_FLAG_ACK) &&
        (state->fin_seen_mask & (1U << (direction ^ 1)))) {
        state->tcp_state_flags |= TCP_ACK_BIT;
        state->fin_ack_seen_mask |= 1U << direction;
    }
    if (flags & TCP_FLAG_FIN) {
        state->tcp_state_flags |= TCP_FIN_BIT;
        state->fin_seen_mask |= 1U << direction;
    }
    if (flags & TCP_FLAG_RST)
        state->tcp_state_flags |= TCP_RST_BIT;
    if (state->fin_seen_mask == 0x3 && state->fin_ack_seen_mask == 0x3 &&
        state->terminal_deadline_ns == 0)
        state->terminal_deadline_ns = now + grace;
}

/**
 * Deletes native state plus its original, target, and reverse indexes.
 * @param state flow record containing the id/generation and three keys
 * @return TC_ACT_OK so deletion never drops the packet by itself
 */
static __always_inline int delete_flow(const struct flow_state_value *state)
{
    struct flow_state_key state_key = {
        .version = bpf_htons(MAP_ABI_VERSION),
        .flow_id = state->flow_id,
        .generation = state->generation,
    };
    bpf_map_delete_elem(&ssp_flow_index_v1, &state->original);
    bpf_map_delete_elem(&ssp_flow_index_v1, &state->target);
    bpf_map_delete_elem(&ssp_flow_index_v1, &state->reverse);
    bpf_map_delete_elem(&ssp_flow_state_v1, &state_key);
    release_flow_slot();
    return TC_ACT_OK;
}

/**
 * Deletes an index only when it still belongs to the supplied flow generation.
 * This ownership check prevents a stale cleanup from deleting a newer flow.
 * @param key tuple index to inspect
 * @param owner expected flow id and generation
 */
static __always_inline void delete_owned_index(const struct tuple_key *key,
                                               const struct flow_index_value *owner)
{
    struct flow_index_value *current =
        bpf_map_lookup_elem(&ssp_flow_index_v1, key);
    if (current && current->flow_id == owner->flow_id &&
        current->generation == owner->generation)
        bpf_map_delete_elem(&ssp_flow_index_v1, key);
}

/**
 * Resolves or creates a flow-map entry, applies direction-specific tuple
 * rewriting, records TCP lifecycle state, and removes terminal flows.
 * Missing targets, capacity failures, malformed state, and unsupported
 * packets leave the packet unchanged or return the verifier-safe action
 * selected by the existing failure path.
 * @param skb packet classified by TC
 * @param ingress true for destination rewrite, false for reverse restoration
 * @return TC_ACT_OK for pass/rewrite, or TC_ACT_SHOT when flow allocation
 *         cannot be completed
 */
static __always_inline int process_packet(struct __sk_buff *skb, bool ingress)
{
    struct packet_info packet = {};
    struct tuple_key lookup_key = {};
    struct flow_index_value *index;
    struct flow_index_value resolved_index = {};
    struct flow_state_key state_key = {};
    struct flow_state_value *state;
    struct flow_state_value *candidate;
    struct flow_index_value candidate_index = {};
    __u8 have_index = 0;
    __u64 now;
    __u64 flow_id;
    __be16 target_port;
    __u8 target[16];
    __u8 direction;
    __u32 scratch_key = 0;

    if (!parse_packet(skb, &packet))
        return TC_ACT_OK;
    if (is_control_packet(&packet, ingress)) {
        increment_counter(2);
        return TC_ACT_OK;
    }

    if (ingress) {
        make_tuple_key(&lookup_key, &packet, packet.source, packet.destination,
                       packet.source_port, packet.destination_port);
    } else {
        make_tuple_key(&lookup_key, &packet, packet.source, packet.destination,
                       packet.source_port, packet.destination_port);
    }
    index = bpf_map_lookup_elem(&ssp_flow_index_v1, &lookup_key);
    if (index) {
        resolved_index = *index;
        have_index = 1;
    }
    if (!have_index && ingress) {
        if (!target_for_packet(&packet, target, &target_port)) {
            increment_counter(0);
            return TC_ACT_OK;
        }
        flow_id = tuple_hash(&lookup_key);
        if (flow_id == 0)
            flow_id = 1;
        candidate = bpf_map_lookup_elem(&ssp_tc_scratch_v1, &scratch_key);
        if (!candidate)
            return TC_ACT_SHOT;
        __builtin_memset(candidate, 0, sizeof(*candidate));
        candidate_index.version = bpf_htons(MAP_ABI_VERSION);
        candidate_index.flow_id = flow_id;
        candidate_index.generation = 1;
        state_key.version = bpf_htons(MAP_ABI_VERSION);
        state_key.flow_id = flow_id;
        state_key.generation = 1;
        candidate->original = lookup_key;
        candidate->target = lookup_key;
        candidate->reverse = lookup_key;
        copy16(candidate->target.destination, target);
        candidate->target.destination_port = target_port;
        copy16(candidate->reverse.source, target);
        copy16(candidate->reverse.destination, packet.source);
        candidate->reverse.source_port = target_port;
        candidate->reverse.destination_port = packet.source_port;
        candidate->flow_id = flow_id;
        candidate->generation = 1;
        candidate->protocol_flags = packet.protocol == IPPROTO_TCP ? 1 : 2;
        candidate->lifecycle = FLOW_CREATING;
        candidate->last_used_ns = bpf_ktime_get_ns();
        if (!reserve_flow_slot()) {
            increment_counter(1);
            return TC_ACT_SHOT;
        }
        if (bpf_map_update_elem(&ssp_flow_state_v1, &state_key, candidate,
                                BPF_NOEXIST) != 0) {
            release_flow_slot();
            index = bpf_map_lookup_elem(&ssp_flow_index_v1, &lookup_key);
            if (!index) {
                increment_counter(1);
                return TC_ACT_SHOT;
            }
            resolved_index = *index;
            have_index = 1;
        } else if (bpf_map_update_elem(&ssp_flow_index_v1, &lookup_key,
                                       &candidate_index, BPF_NOEXIST) != 0 ||
                   bpf_map_update_elem(&ssp_flow_index_v1, &candidate->target,
                                       &candidate_index, BPF_NOEXIST) != 0 ||
                   bpf_map_update_elem(&ssp_flow_index_v1, &candidate->reverse,
                                       &candidate_index, BPF_NOEXIST) != 0) {
            delete_owned_index(&lookup_key, &candidate_index);
            delete_owned_index(&candidate->target, &candidate_index);
            delete_owned_index(&candidate->reverse, &candidate_index);
            bpf_map_delete_elem(&ssp_flow_state_v1, &state_key);
            release_flow_slot();
            index = bpf_map_lookup_elem(&ssp_flow_index_v1, &lookup_key);
            if (!index) {
                increment_counter(1);
                return TC_ACT_SHOT;
            }
            resolved_index = *index;
            have_index = 1;
        } else {
            candidate->lifecycle = FLOW_ACTIVE;
            if (bpf_map_update_elem(&ssp_flow_state_v1, &state_key, candidate,
                                    BPF_EXIST) != 0) {
                delete_owned_index(&lookup_key, &candidate_index);
                delete_owned_index(&candidate->target, &candidate_index);
                delete_owned_index(&candidate->reverse, &candidate_index);
                bpf_map_delete_elem(&ssp_flow_state_v1, &state_key);
                release_flow_slot();
                increment_counter(1);
                return TC_ACT_SHOT;
            }
            resolved_index = candidate_index;
            have_index = 1;
        }
    }
    if (!have_index)
        return TC_ACT_OK;
    state_key.version = bpf_htons(MAP_ABI_VERSION);
    state_key.flow_id = resolved_index.flow_id;
    state_key.generation = resolved_index.generation;
    state = bpf_map_lookup_elem(&ssp_flow_state_v1, &state_key);
    if (!state || state->lifecycle != FLOW_ACTIVE)
        return TC_ACT_OK;

    now = bpf_ktime_get_ns();
    direction = ingress ? 0 : 1;
    if (packet.protocol == IPPROTO_TCP) {
        update_tcp_state(state, direction, packet.tcp_flags, now);
        bpf_map_update_elem(&ssp_flow_state_v1, &state_key, state, BPF_EXIST);
    } else {
        state->last_used_ns = now;
        bpf_map_update_elem(&ssp_flow_state_v1, &state_key, state, BPF_EXIST);
    }

    if (ingress) {
        target_port = state->target.destination_port;
        rewrite_destination(skb, &packet, state->target.destination, target_port);
    } else {
        rewrite_source(skb, &packet, state->original.destination,
                       state->original.destination_port);
    }
    if (packet.protocol == IPPROTO_TCP && (packet.tcp_flags & TCP_FLAG_RST))
        delete_flow(state);
    return TC_ACT_OK;
}

/**
 * Ingress TC entrypoint: resolves/creates a flow, rewrites the destination,
 * and returns `TC_ACT_OK` unless active-flow allocation must drop the packet.
 * @param skb packet received on the ingress hook
 * @return TC action from `process_packet`
 */
SEC("classifier")
int ssp_tc_ingress_v3(struct __sk_buff *skb)
{
    return process_packet(skb, true);
}

/**
 * Egress TC entrypoint: resolves the reverse tuple and restores the original
 * destination address and port.
 * @param skb packet received on the egress hook
 * @return TC action from `process_packet`
 */
SEC("classifier")
int ssp_tc_egress_v3(struct __sk_buff *skb)
{
    return process_packet(skb, false);
}

/** License metadata required by the kernel BPF loader. */
char LICENSE[] SEC("license") = "GPL";
