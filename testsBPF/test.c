// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// Licence obligatoire pour le vérificateur du noyau
char LICENSE[] SEC("license") = "Dual BSD/GPL";

// Attachement du programme sur un tracepoint du noyau (ici : entrée de l'appel système write)
SEC("tp/syscalls/sys_enter_write")
int handle_write_entry(void *ctx) {
    // Affiche un message dans le tampon de trace du noyau (/sys/kernel/tracing/trace_pipe)
    bpf_printk("Hello eBPF! Un appel systeme write a ete detecte.\n");
    
    return 0;
}

