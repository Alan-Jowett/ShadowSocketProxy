// SPDX-License-Identifier: MIT
// Copyright (c) 2026 ShadowSocketProxy contributors

/*
 * Build with a Linux clang toolchain and the kernel UAPI headers:
 *
 *   clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
 *     -I/usr/include/$(uname -m)-linux-gnu -c placeholder.bpf.c \
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
#define SEC(name) __attribute__((section(name), used))
#endif

#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif

#ifndef bpf_htons
#define bpf_htons(x) (__builtin_bswap16((__u16)(x)))
#define bpf_ntohs(x) (__builtin_bswap16((__u16)(x)))
#endif

#ifndef __uint
#define __uint(name, value) int (*name)[value]
#define __type(name, value) typeof(value) *name
#endif

static void *(*bpf_map_lookup_elem)(void *map, const void *key) =
    (void *)BPF_FUNC_map_lookup_elem;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value,
                                   __u64 flags) =
    (void *)BPF_FUNC_map_update_elem;
static long (*bpf_map_delete_elem)(void *map, const void *key) =
    (void *)BPF_FUNC_map_delete_elem;
static __u64 (*bpf_ktime_get_ns)(void) = (void *)BPF_FUNC_ktime_get_ns;
static long (*bpf_skb_load_bytes)(const struct __sk_buff *skb, __u32 offset,
                                  void *to, __u32 len) =
    (void *)BPF_FUNC_skb_load_bytes;
static long (*bpf_skb_store_bytes)(struct __sk_buff *skb, __u32 offset,
                                   const void *from, __u32 len, __u64 flags) =
    (void *)BPF_FUNC_skb_store_bytes;
static long (*bpf_l3_csum_replace)(struct __sk_buff *skb, __u32 offset,
                                   __u64 from, __u64 to, __u64 size) =
    (void *)BPF_FUNC_l3_csum_replace;
static long (*bpf_l4_csum_replace)(struct __sk_buff *skb, __u32 offset,
                                   __u64 from, __u64 to, __u64 flags) =
    (void *)BPF_FUNC_l4_csum_replace;
static __s64 (*bpf_csum_diff)(__be32 *from, __u32 from_size, __be32 *to,
                              __u32 to_size, __wsum seed) =
    (void *)BPF_FUNC_csum_diff;

#define MAP_ABI_VERSION 1
#define POLICY_KEY_LEN 24
#define POLICY_VALUE_LEN 24
#define FLOW_INDEX_VALUE_LEN 16
#define FLOW_STATE_KEY_LEN 16
#define FLOW_STATE_VALUE_LEN 256
#define POLICY_MAX_ENTRIES 4096
#define FLOW_INDEX_MAX_ENTRIES 16384
#define FLOW_STATE_MAX_ENTRIES 8192

#define FLOW_CREATING 1
#define FLOW_ACTIVE 2
#define TCP_SYN_BIT (1U << 0)
#define TCP_SYN_ACK_BIT (1U << 1)
#define TCP_ACK_BIT (1U << 2)
#define TCP_FIN_BIT (1U << 3)
#define TCP_RST_BIT (1U << 4)
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_ACK 0x10

struct policy_key {
    __be16 version;
    __u8 family;
    __u8 protocol;
    __u8 destination[16];
    __be16 destination_port;
    __u16 reserved;
} __attribute__((packed));

struct policy_value {
    __be16 version;
    __u8 family;
    __u8 reserved;
    __u8 target[16];
    __be16 target_port;
    __u16 reserved2;
} __attribute__((packed));

struct tuple_key {
    __be16 version;
    __u8 family;
    __u8 protocol;
    __u8 source[16];
    __u8 destination[16];
    __be16 source_port;
    __be16 destination_port;
} __attribute__((packed));

struct flow_index_value {
    __be16 version;
    __u16 reserved;
    __u64 flow_id;
    __u32 generation;
} __attribute__((packed));

struct flow_state_key {
    __be16 version;
    __u16 reserved;
    __u64 flow_id;
    __u32 generation;
} __attribute__((packed));

struct flow_state_value {
    struct tuple_key original;
    struct tuple_key target;
    struct tuple_key reverse;
    __u64 last_used_ns;
    __u32 protocol_flags;
    __u32 tcp_state_flags;
    __u8 fin_seen_mask;
    __u8 fin_ack_seen_mask;
    __u8 lifecycle;
    __u8 reserved;
    __u64 terminal_deadline_ns;
    __u64 flow_id;
    __u32 generation;
    __u8 padding[96];
} __attribute__((packed));

struct counter_value {
    __u64 value;
};

struct runtime_config_value {
    __u64 idle_ttl_ns;
    __u64 terminal_grace_ns;
    __u32 policy_capacity;
    __u32 flow_capacity;
};

struct packet_info {
    __u32 l3_offset;
    __u32 l4_offset;
    __u32 l4_checksum_offset;
    __u8 family;
    __u8 protocol;
    __u8 tcp_flags;
    __u8 source[16];
    __u8 destination[16];
    __be16 source_port;
    __be16 destination_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, POLICY_MAX_ENTRIES);
    __type(key, struct policy_key);
    __type(value, struct policy_value);
} ssp_destination_policy_map_v1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLOW_INDEX_MAX_ENTRIES);
    __type(key, struct tuple_key);
    __type(value, struct flow_index_value);
} ssp_flow_index_v1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, FLOW_STATE_MAX_ENTRIES);
    __type(key, struct flow_state_key);
    __type(value, struct flow_state_value);
} ssp_flow_state_v1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 8);
    __type(key, __u32);
    __type(value, struct counter_value);
} ssp_tc_counters_v1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct runtime_config_value);
} ssp_runtime_config_v1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct flow_state_value);
} ssp_tc_scratch_v1 SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} ssp_tc_active_flows_v1 SEC(".maps");

static __always_inline void copy4(__u8 *to, const __u8 *from)
{
    to[0] = from[0];
    to[1] = from[1];
    to[2] = from[2];
    to[3] = from[3];
}

static __always_inline void copy16(__u8 *to, const __u8 *from)
{
    __u32 i;
    for (i = 0; i < 16; i++)
        to[i] = from[i];
}

static __always_inline void clear16(__u8 *value)
{
    __u32 i;
    for (i = 0; i < 16; i++)
        value[i] = 0;
}

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

static __always_inline void increment_counter(__u32 index)
{
    struct counter_value *counter = bpf_map_lookup_elem(&ssp_tc_counters_v1, &index);
    if (counter)
        __sync_fetch_and_add(&counter->value, 1);
}

static __always_inline int reserve_flow_slot(void)
{
    __u32 config_key = 0;
    __u64 *count = bpf_map_lookup_elem(&ssp_tc_active_flows_v1, &config_key);
    struct runtime_config_value *config =
        bpf_map_lookup_elem(&ssp_runtime_config_v1, &config_key);
    __u64 previous;

    if (!count)
        return 0;
    previous = __sync_fetch_and_add(count, 1);
    if (config && config->flow_capacity && previous >= config->flow_capacity) {
        __sync_fetch_and_sub(count, 1);
        return 0;
    }
    return 1;
}

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

static __always_inline void make_policy_key(struct policy_key *key,
                                            const struct packet_info *packet)
{
    key->version = bpf_htons(MAP_ABI_VERSION);
    key->family = packet->family;
    key->protocol = packet->protocol;
    copy16(key->destination, packet->destination);
    key->destination_port = packet->destination_port;
    key->reserved = 0;
}

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

static __always_inline void update_tcp_state(struct flow_state_value *state,
                                             __u8 direction,
                                             __u8 flags,
                                             __u64 now)
{
    __u32 config_key = 0;
    struct runtime_config_value *config =
        bpf_map_lookup_elem(&ssp_runtime_config_v1, &config_key);
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

static __always_inline void delete_owned_index(const struct tuple_key *key,
                                               const struct flow_index_value *owner)
{
    struct flow_index_value *current =
        bpf_map_lookup_elem(&ssp_flow_index_v1, key);
    if (current && current->flow_id == owner->flow_id &&
        current->generation == owner->generation)
        bpf_map_delete_elem(&ssp_flow_index_v1, key);
}

static __always_inline int process_packet(struct __sk_buff *skb, bool ingress)
{
    struct packet_info packet = {};
    struct tuple_key lookup_key = {};
    struct flow_index_value *index;
    struct flow_state_key state_key = {};
    struct flow_state_value *state;
    struct policy_key policy_key = {};
    struct policy_value *policy;
    struct flow_state_value *candidate;
    struct flow_index_value candidate_index = {};
    __u64 now;
    __u64 flow_id;
    __be16 target_port;
    __u8 direction;
    __u32 scratch_key = 0;

    if (!parse_packet(skb, &packet))
        return TC_ACT_OK;

    if (ingress) {
        make_tuple_key(&lookup_key, &packet, packet.source, packet.destination,
                       packet.source_port, packet.destination_port);
    } else {
        make_tuple_key(&lookup_key, &packet, packet.source, packet.destination,
                       packet.source_port, packet.destination_port);
    }
    index = bpf_map_lookup_elem(&ssp_flow_index_v1, &lookup_key);
    if (!index && ingress) {
        make_policy_key(&policy_key, &packet);
        policy = bpf_map_lookup_elem(&ssp_destination_policy_map_v1, &policy_key);
        if (!policy) {
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
        copy16(candidate->target.destination, policy->target);
        candidate->target.destination_port = policy->target_port;
        copy16(candidate->reverse.source, policy->target);
        copy16(candidate->reverse.destination, packet.source);
        candidate->reverse.source_port = policy->target_port;
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
            index = &candidate_index;
        }
    }
    if (!index)
        return TC_ACT_OK;
    state_key.version = bpf_htons(MAP_ABI_VERSION);
    state_key.flow_id = index->flow_id;
    state_key.generation = index->generation;
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

SEC("classifier")
int ssp_tc_ingress_v2(struct __sk_buff *skb)
{
    return process_packet(skb, true);
}

SEC("classifier")
int ssp_tc_egress_v2(struct __sk_buff *skb)
{
    return process_packet(skb, false);
}

char LICENSE[] SEC("license") = "GPL";
