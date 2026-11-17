/*
 * kvstore.c — serveur clé-valeur minimal, compatible avec un sous-ensemble
 * du protocole texte de Memcached.
 *
 * Commandes prises en charge :
 *   get <clé> [<clé> ...]                         (multiget possible)
 *   set <clé> <flags> <exptime> <octets> [noreply]\r\n<données>\r\n
 *   delete <clé> [noreply]
 *   quit
 *
 * Transports : TCP et UDP, sur le même port (11211 par défaut).
 *   En UDP, chaque datagramme commence par l'en-tête Memcached de 8 octets
 *   (id de requête, n° de séquence, nombre total de datagrammes, réservé,
 *   tous en ordre réseau). La requête et la réponse doivent tenir dans un
 *   seul datagramme.
 *
 * Choix volontairement naïfs (points de départ pour le projet) :
 *   - table de hachage à chaînage protégée par UN SEUL verrou
 *     lecteurs/rédacteur ;
 *   - UNE SEULE socket UDP partagée par tous les threads UDP
 *     (comme Memcached « vanilla ») ;
 *   - un thread par connexion TCP ;
 *   - exptime ignoré, pas de limite mémoire ni d'éviction.
 *
 * Compilation : make
 * Usage       : ./kvstore [-p port] [-t nb_threads_udp] [-v]
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define DEFAULT_PORT     11211
#define DEFAULT_THREADS  4
#define MAX_KEY_LEN      250              /* limite du protocole Memcached */
#define MAX_VALUE_LEN    (1024 * 1024)
#define MAX_LINE_LEN     8192
#define NBUCKETS         (1u << 20)
#define UDP_HDR_LEN      8
#define UDP_MAX_DGRAM    1400             /* taille max d'une réponse UDP */

static int verbose;

/* ======================================================================
 * Table de hachage
 * ====================================================================== */

struct item {
    struct item *next;
    uint32_t hash;
    uint32_t flags;
    uint32_t klen;
    uint32_t vlen;
    char data[];                          /* clé, puis valeur */
};

static struct item **table;
static pthread_rwlock_t table_lock = PTHREAD_RWLOCK_INITIALIZER;

/* FNV-1a 32 bits (la même fonction que celle utilisée par BMC). */
static uint32_t fnv1a(const char *s, size_t n)
{
    uint32_t h = 2166136261u;
    for (size_t i = 0; i < n; i++) {
        h ^= (uint8_t)s[i];
        h *= 16777619u;
    }
    return h;
}

/* Renvoie l'adresse du pointeur vers l'élément cherché (ou vers le NULL
 * de fin de chaîne s'il est absent). Appeler avec le verrou pris. */
static struct item **lookup_slot(const char *key, size_t klen, uint32_t h)
{
    struct item **pp = &table[h % NBUCKETS];
    for (; *pp; pp = &(*pp)->next) {
        struct item *it = *pp;
        if (it->hash == h && it->klen == klen &&
            memcmp(it->data, key, klen) == 0)
            break;
    }
    return pp;
}

/* Copie la valeur dans dst (capacité MAX_VALUE_LEN).
 * Renvoie 1 si la clé existe, 0 sinon. */
static int kv_get(const char *key, size_t klen, char *dst,
                  uint32_t *vlen, uint32_t *flags)
{
    uint32_t h = fnv1a(key, klen);
    int found = 0;

    pthread_rwlock_rdlock(&table_lock);
    struct item *it = *lookup_slot(key, klen, h);
    if (it) {
        memcpy(dst, it->data + it->klen, it->vlen);
        *vlen = it->vlen;
        *flags = it->flags;
        found = 1;
    }
    pthread_rwlock_unlock(&table_lock);
    return found;
}

/* Insère ou remplace. Renvoie 0 en cas de succès, -1 si malloc échoue. */
static int kv_set(const char *key, size_t klen, uint32_t flags,
                  const char *val, size_t vlen)
{
    struct item *it = malloc(sizeof *it + klen + vlen);
    if (!it)
        return -1;
    it->hash = fnv1a(key, klen);
    it->flags = flags;
    it->klen = klen;
    it->vlen = vlen;
    memcpy(it->data, key, klen);
    memcpy(it->data + klen, val, vlen);

    pthread_rwlock_wrlock(&table_lock);
    struct item **pp = lookup_slot(key, klen, it->hash);
    struct item *old = *pp;
    it->next = old ? old->next : NULL;
    *pp = it;
    pthread_rwlock_unlock(&table_lock);

    free(old);
    return 0;
}

/* Renvoie 1 si la clé a été supprimée, 0 si elle n'existait pas. */
static int kv_delete(const char *key, size_t klen)
{
    uint32_t h = fnv1a(key, klen);

    pthread_rwlock_wrlock(&table_lock);
    struct item **pp = lookup_slot(key, klen, h);
    struct item *old = *pp;
    if (old)
        *pp = old->next;
    pthread_rwlock_unlock(&table_lock);

    int found = old != NULL;
    free(old);
    return found;
}

/* ======================================================================
 * Tampon de sortie extensible
 * ====================================================================== */

struct buf {
    char *data;
    size_t len, cap;
};

static void buf_append(struct buf *b, const void *p, size_t n)
{
    if (b->len + n > b->cap) {
        size_t nc = b->cap ? b->cap : 4096;
        while (nc < b->len + n)
            nc *= 2;
        b->data = realloc(b->data, nc);
        if (!b->data) {
            perror("realloc");
            exit(EXIT_FAILURE);
        }
        b->cap = nc;
    }
    memcpy(b->data + b->len, p, n);
    b->len += n;
}

static void buf_puts(struct buf *b, const char *s)
{
    buf_append(b, s, strlen(s));
}

/* ======================================================================
 * Protocole
 * ====================================================================== */

enum { CLOSE = -1, NEED_MORE = 0, DONE = 1 };

static __thread char *valbuf;             /* copie des valeurs, par thread */

static int parse_u32(const char *s, uint32_t *out)
{
    char *end;
    errno = 0;
    unsigned long v = strtoul(s, &end, 10);
    if (errno || *end || end == s || v > UINT32_MAX)
        return -1;
    *out = (uint32_t)v;
    return 0;
}

/*
 * Traite UNE commande au début de `in` (longueur `len`) et ajoute la
 * réponse à `out`.
 *   NEED_MORE : commande incomplète, rien n'est consommé ;
 *   DONE      : commande traitée, *consumed = nombre d'octets lus ;
 *   CLOSE     : erreur fatale, la connexion doit être fermée.
 */
static int process_request(const char *in, size_t len, struct buf *out,
                           size_t *consumed)
{
    const char *eol = memmem(in, len, "\r\n", 2);
    if (!eol)
        return len >= MAX_LINE_LEN ? CLOSE : NEED_MORE;

    size_t line_len = (size_t)(eol - in);
    if (line_len >= MAX_LINE_LEN) {
        buf_puts(out, "CLIENT_ERROR line too long\r\n");
        return CLOSE;
    }

    char line[MAX_LINE_LEN];
    memcpy(line, in, line_len);
    line[line_len] = '\0';
    size_t line_total = line_len + 2;

    if (verbose)
        fprintf(stderr, "<< %s\n", line);

    char *save, *cmd = strtok_r(line, " ", &save);
    if (!cmd) {
        *consumed = line_total;
        buf_puts(out, "ERROR\r\n");
        return DONE;
    }

    /* ---- get <clé>* ---- */
    if (strcmp(cmd, "get") == 0) {
        if (!valbuf && !(valbuf = malloc(MAX_VALUE_LEN))) {
            perror("malloc");
            exit(EXIT_FAILURE);
        }
        size_t start = out->len;
        int nkeys = 0;
        char *key;
        *consumed = line_total;

        while ((key = strtok_r(NULL, " ", &save))) {
            size_t klen = strlen(key);
            nkeys++;
            if (klen > MAX_KEY_LEN) {
                out->len = start;
                buf_puts(out, "CLIENT_ERROR key too long\r\n");
                return DONE;
            }
            uint32_t vlen, flags;
            if (kv_get(key, klen, valbuf, &vlen, &flags)) {
                char hdr[MAX_KEY_LEN + 64];
                int n = snprintf(hdr, sizeof hdr, "VALUE %s %u %u\r\n",
                                 key, flags, vlen);
                buf_append(out, hdr, (size_t)n);
                buf_append(out, valbuf, vlen);
                buf_puts(out, "\r\n");
            }
        }
        if (nkeys == 0) {
            buf_puts(out, "ERROR\r\n");
            return DONE;
        }
        buf_puts(out, "END\r\n");
        return DONE;
    }

    /* ---- set <clé> <flags> <exptime> <octets> [noreply] ---- */
    if (strcmp(cmd, "set") == 0) {
        char *key = strtok_r(NULL, " ", &save);
        char *sflags = strtok_r(NULL, " ", &save);
        char *sexp = strtok_r(NULL, " ", &save);
        char *sbytes = strtok_r(NULL, " ", &save);
        char *snoreply = strtok_r(NULL, " ", &save);
        uint32_t flags, exptime, bytes;

        if (!key || !sflags || !sexp || !sbytes ||
            parse_u32(sflags, &flags) || parse_u32(sexp, &exptime) ||
            parse_u32(sbytes, &bytes)) {
            buf_puts(out, "CLIENT_ERROR bad command line format\r\n");
            return CLOSE;              /* on ne sait pas combien sauter */
        }
        (void)exptime;                 /* non géré */

        size_t klen = strlen(key);
        if (klen > MAX_KEY_LEN) {
            buf_puts(out, "CLIENT_ERROR key too long\r\n");
            return CLOSE;
        }
        if (bytes > MAX_VALUE_LEN) {
            buf_puts(out, "SERVER_ERROR object too large for cache\r\n");
            return CLOSE;
        }

        size_t total = line_total + bytes + 2;
        if (len < total)
            return NEED_MORE;

        const char *val = in + line_total;
        if (memcmp(val + bytes, "\r\n", 2) != 0) {
            buf_puts(out, "CLIENT_ERROR bad data chunk\r\n");
            return CLOSE;
        }
        *consumed = total;

        int noreply = snoreply && strcmp(snoreply, "noreply") == 0;
        if (kv_set(key, klen, flags, val, bytes) < 0)
            buf_puts(out, "SERVER_ERROR out of memory\r\n");
        else if (!noreply)
            buf_puts(out, "STORED\r\n");
        return DONE;
    }

    /* ---- delete <clé> [noreply] ---- */
    if (strcmp(cmd, "delete") == 0) {
        char *key = strtok_r(NULL, " ", &save);
        char *snoreply = strtok_r(NULL, " ", &save);
        *consumed = line_total;

        if (!key || strlen(key) > MAX_KEY_LEN) {
            buf_puts(out, "CLIENT_ERROR bad command line format\r\n");
            return DONE;
        }
        int found = kv_delete(key, strlen(key));
        if (!(snoreply && strcmp(snoreply, "noreply") == 0))
            buf_puts(out, found ? "DELETED\r\n" : "NOT_FOUND\r\n");
        return DONE;
    }

    /* ---- quit ---- */
    if (strcmp(cmd, "quit") == 0) {
        *consumed = line_total;
        return CLOSE;
    }

    *consumed = line_total;
    buf_puts(out, "ERROR\r\n");
    return DONE;
}

/* ======================================================================
 * Serveur TCP : un thread par connexion
 * ====================================================================== */

static int send_all(int fd, const char *p, size_t n)
{
    while (n > 0) {
        ssize_t w = send(fd, p, n, 0);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += w;
        n -= (size_t)w;
    }
    return 0;
}

static void *tcp_conn_thread(void *arg)
{
    int fd = (int)(intptr_t)arg;
    size_t cap = MAX_LINE_LEN + MAX_VALUE_LEN + 2;
    char *in = malloc(cap);
    struct buf out = {0};
    size_t len = 0;
    int closing = 0;

    if (!in) {
        close(fd);
        return NULL;
    }

    while (!closing) {
        ssize_t n = recv(fd, in + len, cap - len, 0);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            break;
        len += (size_t)n;

        /* Traite toutes les commandes complètes (pipelining). */
        size_t off = 0;
        for (;;) {
            size_t consumed = 0;
            int r = process_request(in + off, len - off, &out, &consumed);
            if (r == NEED_MORE)
                break;
            if (r == CLOSE) {
                closing = 1;
                break;
            }
            off += consumed;
        }

        if (out.len && send_all(fd, out.data, out.len) < 0)
            break;
        out.len = 0;

        memmove(in, in + off, len - off);
        len -= off;
    }

    free(in);
    free(out.data);
    free(valbuf);
    close(fd);
    return NULL;
}

/* ======================================================================
 * Serveur UDP : N threads qui lisent tous la même socket
 * ====================================================================== */

static void *udp_thread(void *arg)
{
    int fd = *(int *)arg;
    char *in = malloc(65536);
    struct buf out = {0};

    if (!in) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }

    for (;;) {
        struct sockaddr_in cli;
        socklen_t clen = sizeof cli;
        ssize_t n = recvfrom(fd, in, 65536, 0, (struct sockaddr *)&cli, &clen);
        if (n < 0) {
            if (errno != EINTR)
                perror("recvfrom");
            continue;
        }
        if (n < UDP_HDR_LEN)
            continue;

        uint16_t total;
        memcpy(&total, in + 4, 2);
        if (ntohs(total) != 1)
            continue;                     /* multi-datagrammes non gérés */

        /* En-tête de réponse : même id, séquence 0, 1 datagramme. */
        static const char hdr_rest[6] = {0, 0, 0, 1, 0, 0};
        out.len = 0;
        buf_append(&out, in, 2);
        buf_append(&out, hdr_rest, sizeof hdr_rest);

        size_t off = UDP_HDR_LEN, len = (size_t)n;
        while (off < len) {
            size_t consumed = 0;
            int r = process_request(in + off, len - off, &out, &consumed);
            if (r == NEED_MORE) {
                buf_puts(&out, "CLIENT_ERROR incomplete request\r\n");
                break;
            }
            if (r == CLOSE)
                break;
            off += consumed;
        }

        if (out.len > UDP_MAX_DGRAM) {
            out.len = UDP_HDR_LEN;
            buf_puts(&out, "SERVER_ERROR response too large for UDP\r\n");
        }
        if (out.len > UDP_HDR_LEN &&
            sendto(fd, out.data, out.len, 0,
                   (struct sockaddr *)&cli, clen) < 0)
            perror("sendto");
    }
    return NULL;
}

/* ======================================================================
 * Initialisation
 * ====================================================================== */

static int make_socket(int type, int port)
{
    int fd = socket(AF_INET, type, 0);
    if (fd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons((uint16_t)port),
        .sin_addr.s_addr = htonl(INADDR_ANY),
    };
    if (bind(fd, (struct sockaddr *)&addr, sizeof addr) < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }
    return fd;
}

static void usage(const char *prog)
{
    fprintf(stderr, "Usage : %s [-p port] [-t nb_threads_udp] [-v]\n", prog);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv)
{
    int port = DEFAULT_PORT, nthreads = DEFAULT_THREADS, opt;

    while ((opt = getopt(argc, argv, "p:t:vh")) != -1) {
        switch (opt) {
        case 'p': port = atoi(optarg); break;
        case 't': nthreads = atoi(optarg); break;
        case 'v': verbose = 1; break;
        default:  usage(argv[0]);
        }
    }
    if (port <= 0 || port > 65535 || nthreads <= 0)
        usage(argv[0]);

    signal(SIGPIPE, SIG_IGN);

    table = calloc(NBUCKETS, sizeof *table);
    if (!table) {
        perror("calloc");
        return EXIT_FAILURE;
    }

    static int udp_fd;
    udp_fd = make_socket(SOCK_DGRAM, port);
    int tcp_fd = make_socket(SOCK_STREAM, port);
    if (listen(tcp_fd, 128) < 0) {
        perror("listen");
        return EXIT_FAILURE;
    }

    for (int i = 0; i < nthreads; i++) {
        pthread_t th;
        if (pthread_create(&th, NULL, udp_thread, &udp_fd) != 0) {
            perror("pthread_create");
            return EXIT_FAILURE;
        }
        pthread_detach(th);
    }

    fprintf(stderr, "kvstore : port %d (TCP+UDP), %d thread(s) UDP\n",
            port, nthreads);

    for (;;) {
        int cfd = accept(tcp_fd, NULL, NULL);
        if (cfd < 0) {
            if (errno != EINTR)
                perror("accept");
            continue;
        }
        pthread_t th;
        if (pthread_create(&th, NULL, tcp_conn_thread,
                           (void *)(intptr_t)cfd) != 0) {
            perror("pthread_create");
            close(cfd);
            continue;
        }
        pthread_detach(th);
    }
}
