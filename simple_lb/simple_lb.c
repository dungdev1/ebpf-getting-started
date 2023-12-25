//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define ELB_MAX_NODES 128
#define MAX_CONNECTIONS 55000
#define MAX_PROTOCOL_SUPPORTED 5
#define MAX_PORT_NUMBER 49151
#define MIN_PORT_NUMBER 1024
#define MAX_CSUM_WORDS 32
#define MAX_TCP_SIZE 1448

// static __always_inline unsigned int crc32b(unsigned char *message, unsigned int size);
static __always_inline void memcpy(unsigned char *d, unsigned char *s, unsigned int size);
static __always_inline int generate_random_port();
static __always_inline void printk_packet_info(struct ethhdr *eth, struct iphdr *iph, struct tcphdr *tcph);
static __always_inline __u16 iph_csum(struct iphdr *iph);
__attribute__((__always_inline__)) static inline __u16 caltcpcsum(struct iphdr *iph, struct tcphdr *tcph, void *data_end);
static __always_inline __u16 csum_fold_helper(__u64 csum);

struct route_key
{
    __be32 lb_ip;
    __be16 lb_port;
    __be32 src_ip;
    __be16 src_port;
};

struct route_value
{
    __be32 lb_ip;
    __be16 lb_port;
    __be32 dst_ip;
    __be16 dst_port;

    unsigned char lb_mac[ETH_ALEN];
    unsigned char dst_mac[ETH_ALEN];

    __u8 fin;
};

struct listener_key
{
    __u8 protocol;
    __u8 pad; // 1 byte
    __be16 port;
};

struct listener_value
{
    __be16 dst_port;
    __u16 idle_timeout;
};

struct packet_tuple
{
    unsigned char src_mac[ETH_ALEN];
    __be32 src_ip;
    __be16 src_port;

    unsigned char dst_mac[ETH_ALEN];
    __be32 dst_ip;
    __be16 dst_port;
};

// Store listener
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct listener_key);
    __type(value, struct listener_value);
    __uint(max_entries, MAX_PROTOCOL_SUPPORTED);
} listeners_map SEC(".maps");

// Store upstreams ip queue
struct
{
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __type(value, __u32);
    __uint(max_entries, ELB_MAX_NODES);
} upstreams_map SEC(".maps");

// Store client -> upstream flow information
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct route_key);
    __type(value, struct route_value);
    __uint(max_entries, MAX_CONNECTIONS * 2);
} route_map SEC(".maps");

// Store upstream -> client flow information
// struct {
//     __uint(type, BPF_MAP_TYPE_HASH);
//     __type(key, struct route_key);
//     __type(value, struct route_value);
//     __uint(max_entries, MAX_CONNECTIONS);
// } reverse_route_map SEC(".maps");

// Mac address coressponding to ip address
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u32);
    __type(value, unsigned char[ETH_ALEN]);
    __uint(max_entries, ELB_MAX_NODES);
} arp_tables_map SEC(".maps");

#define TCP_CSUM_OFF (ETH_HLEN + sizeof(struct iphdr) + offsetof(struct iphdr, check))

SEC("xdp")
int simple_lb(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end)
    {
        return XDP_PASS;
    }
    if (eth->h_proto != htons(ETH_P_IP))
    {
        return XDP_PASS;
    }

    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end)
    {
        return XDP_PASS;
    }

    if (iph->protocol != IPPROTO_TCP)
    {
        return XDP_PASS;
    }

    struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr) > data_end)
    {
        return XDP_PASS;
    }
    
    struct listener_key key;
    __u8 from_upstream = 0;

    __builtin_memset(&key, 0, sizeof(key));
    key.protocol = iph->protocol;

    if (bpf_map_lookup_elem(&arp_tables_map, (void *)&iph->saddr) == NULL) {
        // packet from client
        key.port = ntohs(tcph->dest);

        // check listener
        struct listener_value *listener = bpf_map_lookup_elem(&listeners_map, &key);
        if (listener == NULL) {
            return XDP_PASS;
        }
    } else {
        bpf_printk("packet from upstream server");
        from_upstream = 1;
    }

    bpf_printk("\n-------------------------------");

    if (ntohs(tcph->dest)== 80) {
        bpf_printk("iph: protocol %d, daddr %d", iph->protocol, ntohl(iph->daddr));
        bpf_printk("listener: protocol %d, port %d, pad %d", key.protocol, key.port, key.pad);
    }

    // bpf_printk("listener: idle-timeout %d, dest port %d", listener->idle_timeout, listener->dst_port);
    printk_packet_info(eth, iph, tcph);

    // lookup the session information to
    // 1. if client -> upstream, know what server to send (if session already exist)
    // 2. if upstream -> client (session must exist), know what client to send

    struct route_value *route_val;

    // Calculate route key
    // connection tuple: source IP, source port, destination IP, destination port
    struct route_key route_k;
    __builtin_memset(&route_k, 0, sizeof(route_k));
    route_k.src_ip = iph->saddr;
    route_k.src_port = tcph->source;
    route_k.lb_ip = iph->daddr;
    route_k.lb_port = tcph->dest;

    struct packet_tuple packet;
    __builtin_memset(&packet, 0, sizeof(packet));

    struct route_value route;
    route_val = bpf_map_lookup_elem(&route_map, (void *)&route_k);
    if (route_val == NULL)
    {
        __builtin_memset(&route, 0, sizeof(route));
    }
    else
    {
        route = *route_val;
    }
    bpf_printk("testxxx)");
    if (route_val == NULL)
    {
        bpf_printk("new connection (syn packet)");

        // Lookup the upstream ip for new connection
        __u32 upstream_ip;
        if (bpf_map_pop_elem(&upstreams_map, &upstream_ip) != 0)
        {
            bpf_printk("No upstream ip, please check");
            return XDP_PASS;
        }

        if (bpf_map_push_elem(&upstreams_map, &upstream_ip, BPF_EXIST) != 0)
        {
            bpf_printk("cannot push upstream ip back to map");
            return XDP_PASS;
        }

        // Update packet
        memcpy(packet.src_mac, eth->h_dest, ETH_ALEN);
        packet.src_ip = iph->daddr;
        __u16 lb_src_port = htons(generate_random_port());
        packet.src_port = lb_src_port;

        unsigned char *upstream_mac = bpf_map_lookup_elem(&arp_tables_map, &upstream_ip);
        if (upstream_mac == NULL)
        {
            bpf_printk("No upstream mac address, please check");
            return XDP_PASS;
        }
        memcpy(packet.dst_mac, upstream_mac, ETH_ALEN);
        packet.dst_ip = upstream_ip;
        packet.dst_port = htons(4444);

        // Save the route for next packets

        // From client route
        memcpy(route.lb_mac, packet.src_mac, ETH_ALEN);
        route.lb_ip = iph->daddr;
        route.lb_port = packet.src_port;

        memcpy(route.dst_mac, packet.dst_mac, ETH_ALEN);
        route.dst_ip = packet.dst_ip;
        route.dst_port = packet.dst_port;

        if (bpf_map_update_elem(&route_map, (void *)&route_k, &route, BPF_NOEXIST) < 0)
        {
            bpf_printk("add new route failed");
            return XDP_PASS;
        }

        // From upstream route
        // reset route
        __builtin_memset(&route, 0, sizeof(route));
        __builtin_memset(&route_k, 0, sizeof(route_k));

        memcpy(route.lb_mac, eth->h_dest, ETH_ALEN);
        route.lb_ip = iph->daddr;
        route.lb_port = tcph->dest;
        
        memcpy(route.dst_mac, eth->h_source, ETH_ALEN);
        route.dst_ip = iph->saddr;
        route.dst_port = tcph->source;

        route_k.lb_ip = iph->daddr;
        route_k.lb_port = lb_src_port;
        route_k.src_ip = upstream_ip;
        route_k.src_port = htons(4444);

        if (bpf_map_update_elem(&route_map, (void *)&route_k, &route, BPF_NOEXIST) < 0)
        {
            bpf_printk("add new route failed");
            return XDP_PASS;
        }
    }
    else
    {
        bpf_printk("use already route");
        // Gia su connection active

        memcpy(packet.src_mac, route.lb_mac, ETH_ALEN);
        packet.src_ip = route.lb_ip;
        packet.src_port = route.lb_port;
        memcpy(packet.dst_mac, route.dst_mac, ETH_ALEN);
        packet.dst_ip = route.dst_ip;
        packet.dst_port = route.dst_port;

        if (tcph->ack && route.fin) {
            bpf_printk("delete route");
            if (bpf_map_delete_elem(&route_map, (void *)&route_k) < 0)
            {
                bpf_printk("remove route failed");
                return XDP_PASS;
            }

        }

        if (tcph->fin)
        {
            bpf_printk("mark the route sent FIN packet");
            route.fin = 0x01;
            if (bpf_map_update_elem(&route_map, (void *)&route_k, &route, BPF_EXIST) < 0)
            {
                bpf_printk("update route failed");
                return XDP_PASS;
            }
        }
    }

    bpf_printk("update original packet");

    // update original packet
    memcpy(eth->h_source, packet.src_mac, ETH_ALEN);
    iph->saddr = packet.src_ip;
    tcph->source = packet.src_port;
    memcpy(eth->h_dest, packet.dst_mac, ETH_ALEN);
    iph->daddr = packet.dst_ip;
    tcph->dest = packet.dst_port;

    // Update IP checksum
    iph->check = iph_csum(iph);

    // Update TCP checksum
    tcph->check = 0;
    tcph->check = caltcpcsum(iph, tcph, data_end);

    // print final packet info
    printk_packet_info(eth, iph, tcph);
    return XDP_TX;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

static __always_inline __u16
iph_csum(struct iphdr *iph)
{
    iph->check = 0;
    unsigned long long csum = bpf_csum_diff(0, 0, (unsigned int *)iph, sizeof(struct iphdr), 0);
    return csum_fold_helper(csum);
}

/* All credit goes to FedeParola from https://github.com/iovisor/bcc/issues/2463 */
__attribute__((__always_inline__))
static inline __u16 caltcpcsum(struct iphdr *iph, struct tcphdr *tcph, void *data_end)
{
    __u32 csum_buffer = 0;
    __u16 volatile *buf = (void *)tcph;

    // Compute pseudo-header checksum
    csum_buffer += (__u16)iph->saddr;
    csum_buffer += (__u16)(iph->saddr >> 16);
    csum_buffer += (__u16)iph->daddr;
    csum_buffer += (__u16)(iph->daddr >> 16);
    csum_buffer += (__u16)iph->protocol << 8;
    csum_buffer += htons(ntohs(iph->tot_len) - (__u16)(iph->ihl<<2));

    // Compute checksum on tcp header + payload
    for (int i = 0; i < MAX_TCP_SIZE; i += 2) 
    {
        if ((void *)(buf + 1) > data_end) 
        {
            break;
        }

        csum_buffer += *buf;
        buf++;
    }

    if ((void *)buf + 1 <= data_end) 
    {
        // In case payload is not 2 bytes aligned
        csum_buffer += *(__u8 *)buf;
    }

    __u16 csum = (__u16)csum_buffer + (__u16)(csum_buffer >> 16);
    csum = ~csum;

    return csum;
}


static __always_inline __u16
csum_fold_helper(__u64 csum)
{
    int i;
#pragma unroll
    for (i = 0; i < 4; i++)
    {
        if (csum >> 16)
            csum = (csum & 0xffff) + (csum >> 16);
    }
    return ~csum;
}

// static __always_inline unsigned int
// crc32b(unsigned char *message, unsigned int size)
// {
//     // int i, j;
//     int j;
//     unsigned int byte, crc, mask;

//     crc = 0xFFFFFFFF;
//     while (size-- > 0) {
//         byte = *message++;
//         crc = crc ^ byte;
//         for (j = 7; j >= 0; j--) {    // Do eight times.
//             mask = -(crc & 1);
//             crc = (crc >> 1) ^ (0xEDB88320 & mask);
//         }
//     }
//     return ~crc;
// }

static __always_inline void
memcpy(unsigned char *d, unsigned char *s, unsigned int size)
{
    while (size-- > 0)
        *d++ = *s++;
}

static __always_inline int
generate_random_port()
{
    return (bpf_get_prandom_u32() % (MAX_PORT_NUMBER - MIN_PORT_NUMBER + 1)) + MIN_PORT_NUMBER;
}

static __always_inline void
printk_packet_info(struct ethhdr *eth, struct iphdr *iph, struct tcphdr *tcph)
{
    bpf_printk("++++++++++");
    bpf_printk("src mac: %d, dst mac: %d", eth->h_source[0], eth->h_dest[0]);
    bpf_printk("src mac: %d, dst mac: %d", eth->h_source[1], eth->h_dest[1]);
    bpf_printk("src mac: %d, dst mac: %d", eth->h_source[2], eth->h_dest[2]);
    bpf_printk("src mac: %d, dst mac: %d", eth->h_source[3], eth->h_dest[3]);
    bpf_printk("src mac: %d, dst mac: %d", eth->h_source[4], eth->h_dest[4]);
    bpf_printk("src mac: %d, dst mac: %d", eth->h_source[5], eth->h_dest[5]);

    bpf_printk("src ip: %d, dst ip: %d", ntohl(iph->saddr), ntohl(iph->daddr));
    bpf_printk("src port: %d, dst port: %d", ntohs(tcph->source), ntohs(tcph->dest));
}