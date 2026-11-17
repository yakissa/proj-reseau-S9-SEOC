### proj-reseau-S9-SEOC

build on nix 

```bash
nix build .#load-bpf
```

to attach a bpf program in nix

```bash
sudo nix run .#load-bpf <path/to/file.o> <interface>

# exemple
sudo nix run .#load-bpf result/lib/bpf/xdp_kv.o lo
```

run the kvstore server

```bash
sudo nix run .#kvstore
```

run the tests for kvstore

```bash
python3 testsBPF/test_kvstore.py
```

stack trace for BPF prints

```bash
sudo cat /sys/kernel/tracing/trace_pipe
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