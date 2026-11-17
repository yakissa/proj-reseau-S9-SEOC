### proj-reseau-S9-SEOC

commands for testing, part 3

Terminal A
```bash
#on injecte le code bpf src/buildxdp.c
#sur nixos par exemple :
sudo nix run .#buildxdp -- lo --skb
```

Terminal B
```bash
#sniff de paquets pour voir le retour
sudo tcpdump -n -i lo -tttt -vv 'udp and (port 11211)'
```
Terminal C
```bash
#on envoie le paquet xdp pour vérifier qu'on a le paquet retour dans le terminal B
printf '\x00\x01\x00\x00\x00\x01\x00\x00get k\r\n' | nc -u -w1 127.0.0.1 11211
```


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

