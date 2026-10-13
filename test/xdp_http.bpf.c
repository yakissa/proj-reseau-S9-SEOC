#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_http(struct xdp_md *ctx)
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
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
    if (tcp->dest != bpf_htons(80))
        return XDP_PASS;

    unsigned char *payload = (void *)tcp + tcp->doff * 4;
    if ((void *)(payload + 4) > data_end)
        return XDP_PASS;

    if (payload[0] == 'G' && payload[1] == 'E' &&
        payload[2] == 'T' && payload[3] == ' ')
        bpf_printk("Requete HTTP GET recue sur le port 80");

    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
