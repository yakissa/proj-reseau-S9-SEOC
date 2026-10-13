# xdp_kv : filtre XDP qui compte les GET UDP vers kvstore

Programme `xdp_kv.c` (racine du repo). Il compte, sur l'interface choisie :
- clé 0 : datagrammes UDP vers le port 11211
- clé 1 : dont les `get`

Il laisse tout passer (`XDP_PASS`), kvstore répond normalement.

## Prérequis

```bash
sudo apt install clang llvm libbpf-dev linux-tools-common linux-tools-$(uname -r) iproute2 gcc-multilib netcat-openbsd xxd
```

## 1. Lancer kvstore

```bash
cd ~/Documents/proj-reseau-S9-SEOC/toy-kvs
make
./kvstore -t 4 &
ss -tulpn | grep 11211        # une ligne tcp + une ligne udp
```

## 2. Compiler et charger le programme XDP (su)

```bash
cd ~/Documents/proj-reseau-S9-SEOC
IFACE=lo

clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c xdp_kv.c -o xdp_kv.o
sudo ip link set dev $IFACE xdpgeneric obj xdp_kv.o sec xdp
ip link show $IFACE           # doit afficher "xdpgeneric" et "prog/xdp id ..."
```

`-g` est obligatoire (BTF de la map). `xdpgeneric` marche sur toutes les interfaces.

## 3. Envoyer du trafic

```bash
KEY=foo
VAL=bar
LEN=${#VAL}
HOST=localhost
PORT=11211

# 3 GET UDP
for i in 1 2 3; do
  printf "\x00\x01\x00\x00\x00\x01\x00\x00get $KEY\r\n" | nc -u -w1 $HOST $PORT | xxd
done

# 1 SET UDP (UDP vers 11211 mais pas un get)
printf "\x00\x01\x00\x00\x00\x01\x00\x00set $KEY 0 0 $LEN\r\n$VAL\r\n" | nc -u -w1 $HOST $PORT | xxd

# 1 GET TCP (ne doit pas être compté)
printf "get $KEY\r\n" | nc -q1 $HOST $PORT
```

## 4. Lire les compteurs (avant de décharger, sinon la map est détruite)

```bash
sudo bpftool map dump name stats
```

Total par clé (PERCPU : une valeur par CPU, à additionner) :

```bash
sudo bpftool map dump name stats -j | python3 -c '
import json, sys
for e in json.load(sys.stdin):
    k = e["key"]
    k = int(k[0], 16) if isinstance(k, list) else k
    t = 0
    for v in e["values"]:
        v = v["value"]
        t += int.from_bytes(bytes(int(x, 16) for x in v), "little") if isinstance(v, list) else v
    print("key", k, "=", t)
'
```

## 5. Résultat attendu

| key | Signification | Valeur |
|---|---|---|
| 0 | datagrammes UDP vers 11211 | 4 (3 get + 1 set) |
| 1 | dont `get` | 3 |

Le GET TCP et les réponses du serveur ne sont pas comptés (le filtre teste UDP et le port destination 11211).

## 6. Décharger

```bash
sudo ip link set dev $IFACE xdpgeneric off
```

Remettre les compteurs à 0 : décharger puis recharger (étape 2).

## 7. Arrêter kvstore

```bash
pkill kvstore
```

## Dépannage

- Compteurs à 0 : mauvaise interface (`ip link show lo`), ou serveur pas lancé.
- Erreur au chargement : message du verifier, vérifier que `-g` est présent.
- `asm/types.h not found` : installer `gcc-multilib` ou garder le `-I` multiarch.
- `nc` refuse `-q` ou `-w` : installer `netcat-openbsd`.