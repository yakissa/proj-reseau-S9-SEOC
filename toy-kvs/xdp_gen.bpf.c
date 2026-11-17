// SPDX-License-Identifier: GPL-2.0
/*
 * Construit un paquet Ethernet/IPv4/UDP complet "from scratch" dans le
 * tampon XDP, puis l'émet (XDP_TX). Ce programme n'est pas attaché à une
 * interface : il est exécuté depuis l'espace utilisateur via BPF_PROG_RUN
 * avec le drapeau BPF_F_TEST_XDP_LIVE_FRAMES (noyau >= 5.18).
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define PAYLOAD_LEN 32

/* Configuration renseignée par l'espace utilisateur avant le chargement */
const volatile __u8  cfg_src_mac[ETH_ALEN] = {};
const volatile __u8  cfg_dst_mac[ETH_ALEN] = {};
const volatile __u32 cfg_src_ip   = 0;   /* ordre réseau */
const volatile __u32 cfg_dst_ip   = 0;   /* ordre réseau */
const volatile __u16 cfg_src_port = 0;   /* ordre réseau */
const volatile __u16 cfg_dst_port = 0;   /* ordre réseau */

struct pkt {
	struct ethhdr eth;
	struct iphdr  ip;
	struct udphdr udp;
	__u8          payload[PAYLOAD_LEN];
} __attribute__((packed));

/* Somme de contrôle IPv4 : en-tête de 20 octets = 10 mots de 16 bits */
static __always_inline __u16 ip_csum(struct iphdr *ip)
{
	__u16 *w = (__u16 *)ip;
	__u32 sum = 0;

#pragma unroll
	for (int i = 0; i < (int)sizeof(*ip) / 2; i++)
		sum += w[i];
	sum = (sum & 0xffff) + (sum >> 16);
	sum = (sum & 0xffff) + (sum >> 16);
	return (__u16)~sum;
}

SEC("xdp")
int xdp_gen(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	struct pkt *p  = data;

	/* Le tampon fourni par l'espace utilisateur doit faire exactement
	 * sizeof(struct pkt) octets ; on le vérifie pour le vérifieur. */
	if ((void *)(p + 1) > data_end)
		return XDP_ABORTED;

	/* --- Ethernet --- */
#pragma unroll
	for (int i = 0; i < ETH_ALEN; i++) {
		p->eth.h_dest[i]   = cfg_dst_mac[i];
		p->eth.h_source[i] = cfg_src_mac[i];
	}
	p->eth.h_proto = bpf_htons(ETH_P_IP);

	/* --- IPv4 --- */
	p->ip.version  = 4;
	p->ip.ihl      = 5;
	p->ip.tos      = 0;
	p->ip.tot_len  = bpf_htons(sizeof(struct iphdr) + sizeof(struct udphdr) + PAYLOAD_LEN);
	p->ip.id       = 0;
	p->ip.frag_off = bpf_htons(0x4000);           /* DF */
	p->ip.ttl      = 64;
	p->ip.protocol = IPPROTO_UDP;
	p->ip.saddr    = cfg_src_ip;
	p->ip.daddr    = cfg_dst_ip;
	p->ip.check    = 0;
	p->ip.check    = ip_csum((struct iphdr *)((void *)p + sizeof(struct ethhdr)));

	/* --- UDP --- */
	p->udp.source = cfg_src_port;
	p->udp.dest   = cfg_dst_port;
	p->udp.len    = bpf_htons(sizeof(struct udphdr) + PAYLOAD_LEN);
	p->udp.check  = 0;                            /* 0 = pas de checksum (autorisé en IPv4) */

	/* --- Charge utile --- */
	__builtin_memcpy(p->payload, "Hello depuis un programme eBPF!", PAYLOAD_LEN);

	return XDP_TX;   /* émis sur l'interface ctx_in->ingress_ifindex */
}

char LICENSE[] SEC("license") = "GPL";
