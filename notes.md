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


faire un code qui capture les requetes sur le port 80 par exemple
