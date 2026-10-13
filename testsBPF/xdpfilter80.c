#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";


struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} port80_hits SEC(".maps");

SEC("xdp")
int drop_port80(struct xdp_md *ctx)
{
    void *data     = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)          /* check de bornes obligatoire */
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))   /* réseau = big endian */
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;   /* ihl = options IP */
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;

    /* ... dans drop_port80, à la place du simple return : */
    if (tcp->dest == bpf_htons(80)) {
        __u32 key = 0;
        __u64 *cnt = bpf_map_lookup_elem(&port80_hits, &key);
        if (cnt)                 /* le NULL check est exigé par le verifier */
            (*cnt)++;            /* PERCPU : pas besoin d'atomique */
        bpf_printk("port80 depuis %pI4", &ip->saddr);
        return XDP_DROP;
    }

    return XDP_PASS;
}
