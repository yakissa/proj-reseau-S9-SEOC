#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define KV_PORT    11211
#define MC_HDR_LEN 8          /* en-tête Memcached UDP */

#define CACHE_SIZE 1024
#define MAX_KEY 250
#define MAX_VALUE 1000

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

struct cache_entry {
    __u32 valid;
    __u32 key_len;
    __u32 value_len;
    char key[MAX_KEY];
    char value[MAX_VALUE];
};

struct {                                    //Map clé-valeur
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, CACHE_SIZE);
    __type(key, __u32);
    __type(value, struct cache_entry);
} cache SEC(".maps");

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

static __always_inline __u32 uint_to_str(__u32 n, char out[11])   //Conversion d'un nombre en tableau de caractères
{
    __u32 digits = 1;
    __u32 tmp = n;

    #pragma unroll
    for (int i = 0; i < 9; i++) {
        if (tmp < 10)
            break;

        tmp /= 10;
        digits++;
    }

    tmp = n;

    #pragma unroll
    for (int i = 0; i < 10; i++) {
        if (i >= digits)
            break;

        out[digits - 1 - i] = '0' + (tmp % 10);
        tmp /= 10;
    }

    out[digits] = '\0';
    return digits;
}

//Construction du payload réponse | FLAG considérés comme nul pour l'instant
static __always_inline int build_response(             
    struct xdp_md *ctx,
    const char *key,
    __u32 key_len,
    const char *value,
    __u32 value_len
){              

    char str_len[11];
    __u32 size_value_len = uint_to_str(value_len, str_len);

    _u32 response_len = 6 + key_len + flag_len + 1 + size_value_len + value_len + 7   //VALUE + key + flag + nb_chiffres de value_len + \r\n + value + \r\nEND\r\n
    __u32 old_payload_len =
        bpf_ntohs(udp->len) - sizeof(struct udphdr) - 8;
    int delta = response_len - old_payload_len;

    if (bpf_xdp_ajust_tail(ctxn, delta)<0) {        //redimmensionnement du paquet
        return XDP_PASS
    }

    //vérif et recalcul des pointeurs
    void *data = (void *)(long)ctx->data;           
    void *data_end = (void *)(long)ctx->(data_end);

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) 
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip->ihl * 4;
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;
    
    //Ecriture du payload
    char *curseur = (char *)(udp+1) + MEME_CACHED_LEN;    //payload = data + eth + ip + udp + memecached
    const char prefix1[] = "VALUE ";
    for (i=0; i<6; i++){
        if (curseur + 1 > (char *)data_end)
            return XDP_PASS;
        *curseur = prefix1[i];
        curseur++;
    }

    for (i=0; i<key_len; i++){
        if (curseur + 1 > (char *)data_end)
            return XDP_PASS;
        *curseur = key[i];
        curseur++;
    }

    if (curseur + 3 > (char *)data_end)
        return XDP_PASS;
    *curseur++ = ' ';
    *curseur++ = '0';
    *curseur++ = ' ';

    for (i=0; i<size_value_len; i++){
        if (curseur + 1 > (char *)data_end)
            return XDP_PASS;
        *curseur = str_len[i];
        curseur++;
    }

    const char prefix2[] = "\r\n";
    for (i=0; i<2; i++){
            if (curseur + 1 > (char *)data_end)
                return XDP_PASS;
            *curseur = prefix2[i];
            curseur++;
    }

    for (i=0; i<value_len; i++){
        if (curseur + 1 > (char *)data_end)
            return XDP_PASS;
        *curseur = value[i];
        curseur++;
    }

    const char prefix3[] = "\r\nEND\r\n";
    for (i=0; i<7; i++){
            if (curseur + 1 > (char *)data_end)
                return XDP_PASS;
            *curseur = prefix3[i];
            curseur++;
    }

}