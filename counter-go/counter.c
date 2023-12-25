//go:build ignore

#include "counter.h"


struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, long);
    __uint(max_entries, XCOUNTER_MAP_SIZE);
} xcounter_map SEC(".maps");

SEC("xdp")
int xdp_xcounter(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    uint64_t network_header_offset = sizeof(*eth);

    if (data + network_header_offset > data_end) {
        return XDP_PASS;
    }

    uint16_t h_proto = eth->h_proto;
    int protocol_index;

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
        return XDP_ABORTED;

    bpf_printk("start parse packet type: %d, src ip: %d", ntohs(iph->protocol), ntohl(iph->saddr));


    // Check Ether type which identifies the protocol carried in the payload of the frame
    if (h_proto == htons(ETH_P_IP)) {
        protocol_index = parse_ipv4(data + network_header_offset, data_end);
    } else if (h_proto == htons(ETH_P_IPV6)) {
        protocol_index = parse_ipv6(data + network_header_offset, data_end);
    } else {
        protocol_index = 0;
    }

    if (protocol_index == 0) {
        return XDP_PASS;
    }
    
    long *protocol_count = bpf_map_lookup_elem(&xcounter_map, &protocol_index);
    if (protocol_count) {
        (*protocol_count)++;
        bpf_map_update_elem(&xcounter_map, &protocol_index, protocol_count, BPF_ANY);
    }

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static inline int parse_ipv4(void *ip_data, void *data_end)
{
    struct iphdr *ip_header = ip_data;
    if ((void *)&ip_header[1] > data_end)
    {
        return 0;
    }
    return ip_header->protocol;
}

static inline int parse_ipv6(void *ipv6_data, void *data_end)
{
    struct ipv6hdr *ip6_header = ipv6_data;
    if ((void *)&ip6_header[1] > data_end)
    {
        return 0;
    }
    return ip6_header->nexthdr;
}