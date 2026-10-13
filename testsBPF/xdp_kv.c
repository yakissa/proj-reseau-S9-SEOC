#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define KV_PORT    11211
#define MC_HDR_LEN 8          /* en-tête Memcached UDP */

char LICENSE[] SEC("license") = "Dual BSD/GPL";

enum { STAT_UDP_KV = 0, STAT_GET = 1 };

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

static __always_inline void inc(__u32 key)
{
    __u64 *c = bpf_map_lookup_elem(&stats, &key);
    if (c)
        (*c)++;
}

SEC("xdp")
int xdp_kv_filter(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip->ihl * 4;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    if (udp->dest != bpf_htons(KV_PORT))
        return XDP_PASS;

    inc(STAT_UDP_KV);

    /* payload : 8 octets d'en-tête Memcached, puis la commande */
    char *cmd = (char *)(udp + 1) + MC_HDR_LEN;
    if ((void *)(cmd + 4) > data_end)
        return XDP_PASS;

    if (cmd[0] == 'g' && cmd[1] == 'e' && cmd[2] == 't' && cmd[3] == ' ')
        inc(STAT_GET);

    return XDP_PASS;             /* le serveur répond normalement */
}