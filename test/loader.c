#include <bpf/libbpf.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>

static volatile int stop;
static void on_sig(int s) { stop = 1; }

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s <iface>\n", argv[0]); return 1; }

    struct bpf_object *obj = bpf_object__open_file("xdp_http.bpf.o", NULL);
    if (!obj || bpf_object__load(obj)) { fprintf(stderr, "load failed\n"); return 1; }

    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "xdp_http");
    struct bpf_link *link = bpf_program__attach_xdp(prog, if_nametoindex(argv[1]));
    if (libbpf_get_error(link)) { fprintf(stderr, "attach failed\n"); return 1; }

    signal(SIGINT, on_sig);
    printf("attache a %s, Ctrl+C pour quitter\n", argv[1]);
    while (!stop) pause();

    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
