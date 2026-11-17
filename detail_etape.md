# Projet BMC — sous-étapes des étapes 3 à 7

Ce document détaille les étapes 3 à 7 de la « Progression suggérée » du projet BMC (serveur `kvstore`), pour avancer sous-étape par sous-étape.

---

## Étape 3 : filtre XDP (XDP_PASS + compteurs)

**Objectif :** apprendre la chaîne eBPF complète (écrire, compiler, charger, vérifier) sans encore modifier de paquet.

- [ ] **3.1 Environnement.** Installer `clang`/`llvm`, `libbpf`, `bpftool` et les headers du noyau. Vérifier que le noyau est assez récent et expose le BTF (`/sys/kernel/btf/vmlinux`).
- [ ] **3.2 Banc de test.** Éviter `lo` et préférer deux namespaces réseau reliés par une paire `veth` : le client dans l'un, kvstore dans l'autre, XDP attaché côté serveur. `veth` supporte XDP natif, alors que `lo` pose problème, surtout pour `XDP_TX` à l'étape 4.
- [ ] **3.3 Programme minimal.** Une fonction `SEC("xdp")` qui retourne `XDP_PASS`. La charger avec `ip link` ou `bpftool`, vérifier avec `bpftool prog show`, puis la détacher. Le but est de valider la chaîne d'outils avant d'ajouter de la logique.
- [ ] **3.4 Comprendre le contexte.** `ctx->data` et `ctx->data_end` délimitent le paquet. Chaque accès mémoire doit être précédé d'un test de borne, sinon le vérifieur refuse le programme.
- [ ] **3.5 Parser Ethernet.** Vérifier que `h_proto` vaut `ETH_P_IP` (attention à `htons`/`ntohs`).
- [ ] **3.6 Parser IP.** Vérifier que le protocole est UDP. La longueur de l'en-tête est variable (`ihl * 4`), il ne faut donc pas supposer 20 octets.
- [ ] **3.7 Parser UDP.** Comparer le port destination à 11211.
- [ ] **3.8 Parser l'en-tête Memcached.** Sauter les 8 octets, puis vérifier que le payload commence par `get ` (comparer les 4 premiers octets).
- [ ] **3.9 Map de compteurs.** Une `BPF_MAP_TYPE_PERCPU_ARRAY` avec un indice par événement : paquets vus, UDP, port correct, GET. Incrémenter à chaque étape et lire avec `bpftool map dump`.
- [ ] **3.10 Valider.** Lancer `test_kvstore.py` et des `nc -u` avec des requêtes qui ne sont pas des GET, puis vérifier que chaque compteur évolue comme prévu. `bpf_printk` et `/sys/kernel/debug/tracing/trace_pipe` aident au débogage.

---

## Étape 4 : cache et réponse (la plus difficile)

**Objectif :** répondre au GET depuis le pilote, sans que la requête atteigne kvstore.

- [ ] **4.1 Concevoir la map du cache.** Une `BPF_MAP_TYPE_ARRAY` dont chaque case contient : un champ `valid`, la longueur, la clé, et la réponse ou la valeur (taille max bornée, car eBPF n'a pas d'allocation dynamique). Ajouter un `bpf_spin_lock` par case pour éviter les lectures partielles.
- [ ] **4.2 Extraire la clé et calculer FNV-1a en même temps.** Utiliser une boucle bornée (longueur max 250) qui s'arrête sur `\r` ou un espace. Si la requête contient plusieurs clés ou dépasse les limites, faire `XDP_PASS`.
- [ ] **4.3 Calculer l'index** (`hash` modulo la taille de la map, idéalement une puissance de 2 pour un simple masque). Avec la même taille que kvstore (2^20), vous tombez sur la même case que lui, ce qui aide au débogage.
- [ ] **4.4 Lookup.** Faire `bpf_map_lookup_elem`, puis vérifier `valid` et comparer la clé stockée à la clé demandée. La map étant à correspondance directe, une autre clé peut occuper la case (collision).
- [ ] **4.5 Cas miss.** Incrémenter un compteur `miss` et faire `XDP_PASS`.
- [ ] **4.6 Tester d'abord sans l'étape 5.** Remplir une case à la main avec `bpftool map update` pour valider la partie réponse, sans dépendre du remplissage automatique.
- [ ] **4.7 Construire le contenu de la réponse.** Le plus simple est de stocker directement `VALUE <clé> <flags> <taille>\r\n<data>\r\nEND\r\n` dans la case, pour la recopier telle quelle.
- [ ] **4.8 Ajuster la taille du paquet** avec `bpf_xdp_adjust_tail` (la réponse n'a pas la même taille que la requête). Après cet appel, tous les pointeurs vers le paquet sont invalidés : il faut recalculer `data`/`data_end` et refaire les tests de bornes.
- [ ] **4.9 Réécrire les en-têtes.**
  - Échanger les adresses MAC source et destination, puis les IP, puis les ports.
  - Recopier l'identifiant Memcached de la requête, avec séquence 0 et total 1 (voir la Figure 3 du document).
  - Mettre à jour les champs de longueur IP et UDP.
- [ ] **4.10 Checksums.** Recalculer le checksum IP. Pour UDP en IPv4, le mettre à 0 est autorisé et évite un calcul coûteux.
- [ ] **4.11 Copier la donnée** dans le paquet, avec boucle bornée et tests de bornes à chaque accès.
- [ ] **4.12 Retourner `XDP_TX`.** Vérifier avec `tcpdump` côté client que la réponse arrive, et avec les compteurs de kvstore ou `strace` qu'il n'a rien reçu pour ce GET.

---

## Étape 5 : TC egress (remplissage du cache)

**Objectif :** apprendre au cache à se remplir à partir des vraies réponses de kvstore.

- [ ] **5.1 Comprendre le hook.** TC egress voit les paquets sortants sous forme de `sk_buff`, alors que XDP manipule des `xdp_md`. L'API est différente.
- [ ] **5.2 Attacher le programme.** Créer le qdisc `clsact` sur l'interface, puis `tc filter add dev <if> egress bpf da obj ... sec tc`.
- [ ] **5.3 Filtrer.** Ne garder que l'UDP avec port source 11211 dont le payload (après l'en-tête de 8 octets) commence par `VALUE `.
- [ ] **5.4 Rendre le paquet lisible.** Appeler `bpf_skb_pull_data` pour s'assurer que les données sont contiguës avant de les pointer.
- [ ] **5.5 Parser la réponse.** Extraire la clé, les flags et la taille. Ignorer les réponses trop grandes pour une case ou contenant plusieurs `VALUE`.
- [ ] **5.6 Recalculer le hash et l'index.** Ils doivent être identiques à ceux de l'étape 4 : factoriser ce code dans un header commun.
- [ ] **5.7 Écrire dans la map** sous spin lock, puis marquer `valid`.
- [ ] **5.8 Toujours retourner `TC_ACT_OK`.** Ce programme observe, il ne doit jamais perturber la réponse.
- [ ] **5.9 Valider le cycle complet.** Premier GET : miss, kvstore répond, la case se remplit. Deuxième GET : hit, avec le compteur `hit` qui augmente et kvstore qui ne voit rien.

---

## Étape 6 : invalidation par les SET TCP

**Objectif :** ne jamais servir une valeur périmée.

- [ ] **6.1 Étendre le parseur XDP** pour reconnaître aussi TCP (IP proto 6) avec port destination 11211. Attention à `doff` : l'en-tête TCP a une longueur variable.
- [ ] **6.2 Détecter `set `** au début du payload TCP. Comme TCP est un flux, un `set` peut être coupé ou ne pas être en début de segment. Il faut décider quels cas vous traitez et lesquels vous laissez passer, et le documenter.
- [ ] **6.3 Extraire la clé, calculer le hash et l'index** avec le même code que les étapes 4 et 5.
- [ ] **6.4 Invalider** la case sous spin lock (`valid = 0`), si la clé correspond.
- [ ] **6.5 Toujours retourner `XDP_PASS`.** Le SET doit atteindre kvstore.
- [ ] **6.6 Réfléchir aux courses.** Une réponse GET partie avant un SET peut repeupler le cache avec l'ancienne valeur. Regardez comment l'article traite ce point et notez la limite que vous acceptez.
- [ ] **6.7 Tester la cohérence.** Faire `set foo` puis `get foo` deux fois, puis `set foo` avec une autre valeur et `get foo` : il doit renvoyer la nouvelle valeur. Ajouter ce scénario à `test_kvstore.py`. Le `delete` en TCP peut être traité en bonus de la même façon.

---

## Étape 7 : évaluation

**Objectif :** produire des mesures comparables à celles de l'article.

- [ ] **7.1 Fixer le protocole.** Charge Zipf 0,99, proportion de GET/SET, taille des clés et valeurs, durée de chaque run, nombre de répétitions.
- [ ] **7.2 Trois configurations.** kvstore avec une socket partagée, kvstore avec `SO_REUSEPORT`, et kvstore avec BMC. Faire varier le nombre de threads et de cœurs.
- [ ] **7.3 Générateur de charge.** Mesurer le débit et la latence en percentiles (médiane, p99), pas seulement la moyenne.
- [ ] **7.4 Taux de succès du cache.** Lire les compteurs hit/miss et le faire varier avec la taille du cache et le biais de la distribution.
- [ ] **7.5 Charge défavorable.** Envoyer des valeurs plus grandes que ce que le cache accepte, et mesurer le surcoût de BMC quand il ne sert à rien (le programme XDP s'exécute quand même sur chaque paquet).
- [ ] **7.6 Impact des SET.** Faire varier la proportion de SET et observer l'effet des invalidations sur le taux de succès.
- [ ] **7.7 Profiler avec `perf`.** Comparer la répartition du temps CPU (pile réseau, appels système, verrou de socket) entre les configurations pour retrouver les observations de l'article.
- [ ] **7.8 Rendre les mesures fiables.** Épingler les threads et les IRQ, fixer la fréquence CPU, répéter les runs et reporter la variance.
- [ ] **7.9 Présenter.** Des courbes débit et latence en fonction du nombre de threads, avec les trois configurations sur chaque graphique, comme dans l'article.

---

> Les étapes 3 et 4 portent l'essentiel de la difficulté technique : mieux vaut les prendre sous-étape par sous-étape plutôt que d'écrire tout le programme d'un coup.