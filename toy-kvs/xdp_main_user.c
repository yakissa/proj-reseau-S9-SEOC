// SPDX-License-Identifier: GPL-2.0
/*
 * Chargeur : charge xdp_gen.bpf.o (générateur) et xdp_main.bpf.o
 * (programme principal), place xdp_gen dans la table de tail calls de
 * xdp_main, puis attache xdp_main à l'interface jusqu'à Ctrl-C.
 *
 * Usage : sudo ./xdp_main <iface> <mac_dst> <ip_src> <ip_dst> <port_src> <port_dst> <port_declencheur>
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if_ether.h>
#include <linux/if_link.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>

static volatile sig_atomic_t stop;
static void on_sig(int s) { (void)s; stop = 1; }

static int get_mac(const char *ifname, unsigned char mac[ETH_ALEN])
{
	struct ifreq ifr = {0};
	int fd = socket(AF_INET, SOCK_DGRAM, 0);

	if (fd < 0)
		return -1;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		close(fd);
		return -1;
	}
	memcpy(mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
	close(fd);
	return 0;
}

/* Modifie la valeur initiale d'une variable "const volatile" (.rodata) */
static int set_rodata(struct bpf_object *obj, const char *name, const void *val, size_t len)
{
	struct bpf_map *rodata = bpf_object__find_map_by_name(obj, ".rodata");
	const struct btf *btf = bpf_object__btf(obj);
	size_t sz;
	char *buf;
	int id;

	if (!rodata || !btf)
		return -1;
	buf = bpf_map__initial_value(rodata, &sz);
	id = btf__find_by_name_kind(btf, ".rodata", BTF_KIND_DATASEC);
	if (!buf || id < 0)
		return -1;

	const struct btf_type *sec = btf__type_by_id(btf, id);
	const struct btf_var_secinfo *vs = btf_var_secinfos(sec);
	for (int i = 0; i < btf_vlen(sec); i++, vs++) {
		const struct btf_type *var = btf__type_by_id(btf, vs->type);
		if (strcmp(btf__name_by_offset(btf, var->name_off), name) == 0) {
			if (vs->size != len)
				return -1;
			memcpy(buf + vs->offset, val, len);
			return 0;
		}
	}
	return -1;
}

int main(int argc, char **argv)
{
	unsigned char src_mac[ETH_ALEN], dst_mac[ETH_ALEN];
	struct in_addr src_ip, dst_ip;
	__u16 sport, dport, trig;
	int ifindex, err;

	if (argc != 8) {
		fprintf(stderr, "Usage: %s <iface> <mac_dst> <ip_src> <ip_dst> <port_src> <port_dst> <port_declencheur>\n", argv[0]);
		return 1;
	}
	ifindex = if_nametoindex(argv[1]);
	if (!ifindex || get_mac(argv[1], src_mac)) {
		fprintf(stderr, "Interface %s introuvable\n", argv[1]);
		return 1;
	}
	if (sscanf(argv[2], "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
		   &dst_mac[0], &dst_mac[1], &dst_mac[2],
		   &dst_mac[3], &dst_mac[4], &dst_mac[5]) != 6 ||
	    !inet_pton(AF_INET, argv[3], &src_ip) ||
	    !inet_pton(AF_INET, argv[4], &dst_ip)) {
		fprintf(stderr, "Adresse invalide\n");
		return 1;
	}
	sport = htons(atoi(argv[5]));
	dport = htons(atoi(argv[6]));
	trig  = htons(atoi(argv[7]));

	/* 1. Générateur */
	struct bpf_object *gen = bpf_object__open_file("xdp_gen.bpf.o", NULL);
	if (!gen ||
	    set_rodata(gen, "cfg_src_mac", src_mac, ETH_ALEN) ||
	    set_rodata(gen, "cfg_dst_mac", dst_mac, ETH_ALEN) ||
	    set_rodata(gen, "cfg_src_ip", &src_ip.s_addr, 4) ||
	    set_rodata(gen, "cfg_dst_ip", &dst_ip.s_addr, 4) ||
	    set_rodata(gen, "cfg_src_port", &sport, 2) ||
	    set_rodata(gen, "cfg_dst_port", &dport, 2) ||
	    (err = bpf_object__load(gen))) {
		fprintf(stderr, "Chargement de xdp_gen.bpf.o impossible\n");
		return 1;
	}
	int gen_fd = bpf_program__fd(bpf_object__find_program_by_name(gen, "xdp_gen"));

	/* 2. Programme principal */
	struct bpf_object *main_obj = bpf_object__open_file("xdp_main.bpf.o", NULL);
	if (!main_obj ||
	    set_rodata(main_obj, "cfg_trigger_port", &trig, 2) ||
	    (err = bpf_object__load(main_obj))) {
		fprintf(stderr, "Chargement de xdp_main.bpf.o impossible\n");
		return 1;
	}
	int main_fd = bpf_program__fd(bpf_object__find_program_by_name(main_obj, "xdp_main"));
	int jmp_fd  = bpf_map__fd(bpf_object__find_map_by_name(main_obj, "jmp_table"));

	/* 3. Brancher xdp_gen dans la table de tail calls */
	__u32 key = 0;
	if (bpf_map_update_elem(jmp_fd, &key, &gen_fd, BPF_ANY)) {
		perror("Mise à jour de jmp_table");
		return 1;
	}

	/* 4. Attacher xdp_main (mode natif si le pilote le permet, sinon générique) */
	if ((err = bpf_xdp_attach(ifindex, main_fd, 0, NULL))) {
		fprintf(stderr, "Attachement XDP impossible : %s\n", strerror(-err));
		return 1;
	}
	printf("xdp_main attaché sur %s, déclencheur : UDP port %s. Ctrl-C pour arrêter.\n",
	       argv[1], argv[7]);

	signal(SIGINT, on_sig);
	signal(SIGTERM, on_sig);
	while (!stop)
		pause();

	bpf_xdp_detach(ifindex, 0, NULL);
	bpf_object__close(main_obj);
	bpf_object__close(gen);
	printf("\nDétaché.\n");
	return 0;
}
