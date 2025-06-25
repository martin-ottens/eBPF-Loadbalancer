#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <linux/if_link.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "common.h"

__u32 vip = 0;
__u8 ttl_dec_en = 1;
__u8 af_xdp_en = 0;

#define AF_INET 2

// Mapping: Service Map Key -> Service Address + Enabled Flag
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, service_entry_t);
    __uint(max_entries, LB_SERVICE_LEN);
} service_map SEC(".maps");

// Mapping: Mod Connection Hash -> Service Map Key
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, LB_LOOKUP_LEN);
} lookup_map SEC(".maps");

// Mapping: Connection Hash -> Service Map Key
// Since RSS will take care of forwarding all packets from a single 5-tuple
// connection to a fixed CPU, this map is only required for the case that
// a service comes back online when a connection is currently routed to
// an alternate service
struct {
    __uint(type, BPF_MAP_TYPE_LRU_PERCPU_HASH);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, CONNTRACK_MAP_PERCPU_LEN);
} conntrack_map SEC(".maps");

// Mapping: Netdev RX queue -> AF_XDP socket
struct {
    __uint(type, BPF_MAP_TYPE_XSKMAP);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} xsks_map SEC(".maps");

static __always_inline __u32 hash_tuple(__u32 src_ip, __u32 dst_ip, 
    __u16 src_port, __u16 dst_port) 
{
    __u64 input = ((__u64) src_ip << 32) | dst_ip;
    input ^= ((__u64) src_port << 16) | dst_port;

    input ^= (input >> 33);
    input *= 0xff51afd7ed558ccd;
    input ^= (input >> 33);
    input *= 0xc4ceb9fe1a85ec53;
    input ^= (input >> 33);

    return (__u32) input;
}

static __always_inline __u32 lookup_service(const __u32 hash)
{
    __u32 *service_key;
    service_entry_t *service;
    __s32 cpuid = bpf_get_smp_processor_id();

    service_key = bpf_map_lookup_percpu_elem(&conntrack_map, &hash, cpuid);
    if (service_key && *service_key != 0) {
        service = bpf_map_lookup_elem(&service_map, service_key);
        if (service && service->active)
            return service->addr;
    } 

    __s32 lookup_attempt;
    __u32 lookup_hash = hash;

    #pragma unroll
    for (lookup_attempt = 0; lookup_attempt < LB_LOOKUP_LEN; lookup_attempt++) {
        lookup_hash = lookup_hash % LB_LOOKUP_LEN;
        __u32 *service_key = bpf_map_lookup_elem(&lookup_map, &lookup_hash);

        if (service_key && *service_key != -1) {
            service = bpf_map_lookup_elem(&service_map, service_key);
            if (service && service->active) {
                bpf_map_update_elem(&conntrack_map, &hash, service_key, BPF_ANY);
                return service->addr;
            }
        }
        
        lookup_hash++;
    }

    return 0;
}

static __always_inline void decrement_ttl(struct iphdr *iph)
{
    __u8 ttl0 = iph->ttl;
    iph->ttl--;

    __u16 check0 = iph->check;
    __u32 checksum = (~check0 & 0xFFFF) + (~bpf_htons(ttl0 << 8) & 0xFFFF) + bpf_htons(iph->ttl << 8);
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    checksum = (checksum & 0xFFFF) + (checksum >> 16);
    iph->check = ~checksum;
}

SEC("xdp")
int xdp_lb(struct xdp_md *ctx)
{
    void *data = (void *)(long) ctx->data;
    void *data_end = (void *)(long) ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;
    
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;
    
    if (iph->protocol != IPPROTO_TCP)
        return XDP_PASS;

    if (iph->daddr != bpf_htonl(vip))
        return XDP_PASS;

    struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);
    if ((void *)(tcph + 1) > data_end)
        return XDP_PASS;

    if (iph->ttl <= 1)
        return XDP_DROP;
    
    __u32 lookup_value = hash_tuple(iph->saddr, iph->daddr, tcph->source, tcph->dest);
    __u32 target_ip = lookup_service(lookup_value);

    if (target_ip == 0) {
        bpf_printk("No service available to look up!\n");
        return XDP_DROP;
    }

    struct bpf_fib_lookup fib_lookup = { 0 };
    fib_lookup.family = AF_INET;
    fib_lookup.ifindex = ctx->ingress_ifindex;
    fib_lookup.ipv4_dst = bpf_htonl(target_ip);
    fib_lookup.ipv4_src = iph->saddr;
    fib_lookup.l4_protocol = iph->protocol;
    fib_lookup.tot_len = bpf_ntohs(iph->tot_len);

    __u64 rc = bpf_fib_lookup(ctx, &fib_lookup, sizeof(fib_lookup), 
                             BPF_FIB_LOOKUP_OUTPUT);

    //__u32 qindex = ctx->rx_queue_index;
    __u32 qindex = 0; // Simplification: Only one ring in AF_XDP

    switch (rc) {
        case BPF_FIB_LKUP_RET_BLACKHOLE:
        case BPF_FIB_LKUP_RET_UNREACHABLE:
        case BPF_FIB_LKUP_RET_PROHIBIT:
            return XDP_DROP;
        case BPF_FIB_LKUP_RET_SUCCESS:
            break;
        case BPF_FIB_LKUP_RET_NO_NEIGH:
            if (!af_xdp_en)
                return XDP_DROP;

            if (bpf_map_lookup_elem(&xsks_map, &qindex)) {
                return bpf_redirect_map(&xsks_map, qindex, 0);
            } else {
                bpf_printk("AF_XDP lookup failed!\n");
                return XDP_DROP;
            }
        default:
            return XDP_PASS;
    }

    if (ttl_dec_en)
        decrement_ttl(iph);

    __builtin_memcpy(eth->h_dest, fib_lookup.dmac, ETH_ALEN);
    __builtin_memcpy(eth->h_source, fib_lookup.smac, ETH_ALEN);

    return XDP_TX;
}

char LICENSE[] SEC("license") = "GPL";
