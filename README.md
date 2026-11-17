### notes

build on nix 

```bash
nix build .#load-bpf
```

run on nix (su)

```bash
nix run .#load-bpf
```

stack trace for BPF prints (su)

```bash
cat /sys/kernel/tracing/trace_pipe
```



build on ubuntu

```bash
clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c xdpfilter80.c -o xdpfilter80.o
```

run on ubuntu (su)

```bash
ip link set dev lo xdpgeneric obj xdpfilter80.o sec xdp
```

stack trace for BPF prints (su)

```bash
cat /sys/kernel/tracing/trace_pipe
```