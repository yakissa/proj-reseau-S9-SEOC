// SPDX-License-Identifier: GPL-2.0
/*
 * Programme XDP "principal", attaché à l'interface. Quand il reçoit un
 * paquet UDP vers le port déclencheur, il redimensionne le tampon à la
 * taille du paquet à générer puis appelle xdp_gen par tail call.
 * xdp_gen réécrit entièrement le tampon et l'émet (XDP_TX).
 *
 * Les autres paquets continuent normalement vers la pile réseau.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define PAYLOAD_LEN 32   /* doit être identique à xdp_gen.bpf.c */
#define PKT_LEN (sizeof(struct ethhdr) + sizeof(struct iphdr) + \
		 sizeof(struct udphdr) + PAYLOAD_LEN)

/* Table de programmes : l'entrée 0 reçoit xdp_gen (remplie par le chargeur) */
struct {
	__uint(type, BPF_MAP_TYPE_PROG_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} jmp_table SEC(".maps");

const volatile __u16 cfg_trigger_port = 0;   /* ordre réseau */

SEC("xdp")
int xdp_main(struct xdp_md *ctx)
{
	void *data     = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;

	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end || eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	struct iphdr *ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end || ip->ihl != 5 || ip->protocol != IPPROTO_UDP)
		return XDP_PASS;

	struct udphdr *udp = (void *)(ip + 1);
	if ((void *)(udp + 1) > data_end || udp->dest != cfg_trigger_port)
		return XDP_PASS;

	/* Ajuster la taille du tampon à exactement PKT_LEN octets.
	 * - Agrandir : par l'avant (adjust_head), car XDP garantit
	 *   XDP_PACKET_HEADROOM (256 o) devant le paquet, alors que la place
	 *   en fin de tampon dépend du pilote (sur veth, adjust_tail échoue).
	 * - Réduire : par la fin (adjust_tail), toujours possible. */
	int delta = (int)PKT_LEN - (int)(data_end - data);
	if (delta > 0) {
		if (bpf_xdp_adjust_head(ctx, -delta))
			return XDP_DROP;
	} else if (delta < 0) {
		if (bpf_xdp_adjust_tail(ctx, delta))
			return XDP_DROP;
	}

	/* Saut vers xdp_gen : en cas de succès, on ne revient jamais ici */
	bpf_tail_call(ctx, &jmp_table, 0);

	/* Échec du tail call (table vide) : le paquet a déjà été modifié */
	return XDP_DROP;
}

char LICENSE[] SEC("license") = "GPL";
