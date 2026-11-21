/* Default-off test observer. No BPF program, map update, route or socket mutation.
 * Run as a separate Android process, never from the consumer's connect path.
 * Sources are sequential snapshots, not atomic state or per-packet attribution.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <linux/bpf.h>
#include <linux/fib_rules.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stopping;
static unsigned sequence;
static void stop(int signum) { (void)signum; stopping = 1; }
static uint64_t boot_ns(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_BOOTTIME, &t)) { perror("clock_gettime"); exit(1); }
    return (uint64_t)t.tv_sec * UINT64_C(1000000000) + (uint64_t)t.tv_nsec;
}
static unsigned number(const char *s) {
    char *end;
    errno = 0;
    unsigned long n = strtoul(s, &end, 10);
    if (errno || !*s || *end || n > UINT32_MAX) exit(2);
    return n;
}
static void hex(const void *data, size_t size) {
    const unsigned char *p = data;
    for (size_t i = 0; i < size; i++) printf("%02x", p[i]);
}
static void emit(const char *kind, uint64_t begin, const void *data, size_t size, int error) {
    uint64_t end = boot_ns();
    printf("{\"event\":\"source\",\"sequence\":%u,\"kind\":\"%s\","
           "\"begin_ns\":%" PRIu64 ",\"end_ns\":%" PRIu64 ",\"errno\":%d,\"hex\":\"",
           sequence, kind, begin, end, error);
    hex(data, size);
    puts("\"}");
}
static int map_open(const char *path, unsigned key, unsigned value, const char *kind) {
    union bpf_attr a = {0};
    a.pathname = (uintptr_t)path;
    a.file_flags = BPF_F_RDONLY;
    int fd = syscall(__NR_bpf, BPF_OBJ_GET, &a, sizeof(a));
    if (fd < 0) { perror(path); return -1; }
    struct bpf_map_info info = {0};
    memset(&a, 0, sizeof(a));
    a.info.bpf_fd = fd;
    a.info.info_len = sizeof(info);
    a.info.info = (uintptr_t)&info;
    if (syscall(__NR_bpf, BPF_OBJ_GET_INFO_BY_FD, &a, sizeof(a)) ||
        info.key_size != key || info.value_size != value || info.type != BPF_MAP_TYPE_HASH) {
        fprintf(stderr, "Map schema differs: %s key=%u value=%u type=%u\n",
                kind, info.key_size, info.value_size, info.type);
        close(fd);
        return -1;
    }
    printf("{\"event\":\"map\",\"kind\":\"%s\",\"id\":%u,\"key_size\":%u,\"value_size\":%u}\n",
           kind, info.id, info.key_size, info.value_size);
    return fd;
}
static void lookup(int fd, const void *key, size_t size, const char *kind) {
    uint64_t begin = boot_ns();
    unsigned char value[16] = {0};
    union bpf_attr a = {0};
    a.map_fd = fd;
    a.key = (uintptr_t)key;
    a.value = (uintptr_t)value;
    int rc = syscall(__NR_bpf, BPF_MAP_LOOKUP_ELEM, &a, sizeof(a));
    emit(kind, begin, value, rc ? 0 : size, rc ? errno : 0);
}
static void proc_source(const char *path, const char *kind) {
    uint64_t begin = boot_ns();
    FILE *f = fopen(path, "r");
    char data[65536];
    size_t size = 0;
    int error = 0;
    if (!f) error = errno;
    else {
        size = fread(data, 1, sizeof(data), f);
        if (ferror(f)) error = EIO;
        else if (size == sizeof(data)) error = EOVERFLOW;
        if (fclose(f)) error = EIO;
    }
    emit(kind, begin, data, size, error);
}
static int route_dump(int fd, unsigned type, unsigned family, const char *kind) {
    uint64_t begin = boot_ns();
    struct { struct nlmsghdr h; struct rtgenmsg g; } request = {0};
    request.h.nlmsg_len = NLMSG_LENGTH(sizeof(request.g));
    request.h.nlmsg_type = type;
    request.h.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.h.nlmsg_seq = sequence;
    request.g.rtgen_family = family;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    if (sendto(fd, &request, request.h.nlmsg_len, 0, (struct sockaddr *)&kernel, sizeof(kernel)) !=
        (ssize_t)request.h.nlmsg_len) return -1;
    int done = 0, error = 0;
    size_t used = 0, capacity = 65536;
    unsigned char *saved = malloc(capacity);
    if (!saved) return -1;
    while (!done && !error) {
        union { struct nlmsghdr align; unsigned char bytes[65536]; } buffer;
        struct sockaddr_nl sender = {0};
        struct iovec iov = {.iov_base=buffer.bytes, .iov_len=sizeof(buffer.bytes)};
        struct msghdr message = {.msg_name=&sender, .msg_namelen=sizeof(sender), .msg_iov=&iov, .msg_iovlen=1};
        ssize_t got = recvmsg(fd, &message, 0);
        if (got < 0 && errno == EINTR) continue;
        if (got <= 0 || sender.nl_pid || message.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) {
            error = got < 0 ? errno : EIO;
            break;
        }
        unsigned remaining = (unsigned)got;
        for (struct nlmsghdr *h=(struct nlmsghdr *)buffer.bytes; NLMSG_OK(h, remaining); h=NLMSG_NEXT(h, remaining)) {
            if (h->nlmsg_seq != sequence || h->nlmsg_flags & NLM_F_DUMP_INTR) { error = EIO; break; }
            if (h->nlmsg_type == NLMSG_ERROR) { error = EIO; break; }
            if (h->nlmsg_type == NLMSG_DONE) {
                int status = 0;
                if (h->nlmsg_len >= NLMSG_LENGTH(sizeof(status))) memcpy(&status, NLMSG_DATA(h), sizeof(status));
                if (status) error = EIO;
                done = 1;
            }
        }
        if (remaining) error = EIO;
        if (used + (size_t)got > capacity) {
            capacity = (used + (size_t)got) * 2;
            void *next = realloc(saved, capacity);
            if (!next) { error = ENOMEM; break; }
            saved = next;
        }
        memcpy(saved + used, buffer.bytes, (size_t)got);
        used += (size_t)got;
    }
    emit(kind, begin, saved, used, error);
    free(saved);
    return error ? -1 : 0;
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--boottime")) {
        printf("%" PRIu64 "\n", boot_ns());
        return 0;
    }
    if (argc != 7 || strcmp(argv[1], "--enable-r06-observer")) {
        fprintf(stderr, "Usage: r06_async_sampler --enable-r06-observer uid interval-ms duration-ms android-boot-id map-root\n");
        return 2;
    }
    unsigned uid = number(argv[2]), interval = number(argv[3]), duration = number(argv[4]);
    if (!uid || interval < 20 || interval > 50 || !duration) return 2;
    char boot[80] = {0};
    FILE *f = fopen("/proc/sys/kernel/random/boot_id", "r");
    if (!f || !fgets(boot, sizeof(boot), f)) return 1;
    fclose(f);
    boot[strcspn(boot, "\n")] = 0;
    if (strcmp(boot, argv[5])) { fprintf(stderr, "Android boot differs\n"); return 1; }
    char ingress[512], owner[512];
    if (snprintf(ingress, sizeof(ingress), "%s/map_netd_ingress_discard_map", argv[6]) >= (int)sizeof(ingress) ||
        snprintf(owner, sizeof(owner), "%s/map_netd_uid_owner_map", argv[6]) >= (int)sizeof(owner)) return 2;
    int map = map_open(ingress, 16, 8, "ingress");
    if (map < 0) return 1;
    int uidmap = map_open(owner, 4, 8, "uid_owner");
    if (uidmap < 0) { close(map); return 1; }
    int nl = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    struct timeval timeout = {.tv_sec=1};
    if (nl < 0 || setsockopt(nl, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) return 1;
    struct sigaction action = {.sa_handler=stop, .sa_flags=SA_RESTART};
    sigemptyset(&action.sa_mask);
    if (sigaction(SIGTERM, &action, NULL) || sigaction(SIGINT, &action, NULL)) return 1;
    unsigned char keys[2][16] = {{0}};
    if (inet_pton(AF_INET6, "::ffff:172.27.1.1", keys[0]) != 1 ||
        inet_pton(AF_INET6, "fdf0:ce4a:801d::172:27:1:1", keys[1]) != 1) return 1;
    uint64_t start = boot_ns(), target = start, period = (uint64_t)interval * 1000000;
    printf("{\"event\":\"start\",\"boottime_ns\":%" PRIu64 ",\"uid\":%u,\"interval_ms\":%u,\"pid\":%d}\n",
           start, uid, interval, getpid());
    int failed = 0;
    while (!stopping && boot_ns() - start < (uint64_t)duration * 1000000) {
        sequence++;
        uint64_t begin = boot_ns();
        struct timespec wall;
        if (clock_gettime(CLOCK_REALTIME, &wall)) { failed = 1; break; }
        uint64_t wall_ns = (uint64_t)wall.tv_sec * UINT64_C(1000000000) + (uint64_t)wall.tv_nsec;
        uint64_t wall_boot_end = boot_ns();
        lookup(map, keys[0], 8, "ingress4");
        lookup(map, keys[1], 8, "ingress6");
        lookup(uidmap, &uid, 8, "uid_owner");
        for (unsigned family=AF_INET; family <= AF_INET6; family += AF_INET6-AF_INET) {
            if (route_dump(nl, RTM_GETRULE, family, family == AF_INET ? "rules4" : "rules6")) failed = 1;
        }
        if (route_dump(nl, RTM_GETLINK, AF_UNSPEC, "links") ||
            route_dump(nl, RTM_GETADDR, AF_UNSPEC, "addresses")) failed = 1;
        proc_source("/proc/net/snmp", "snmp");
        proc_source("/proc/net/netstat", "netstat");
        uint64_t end = boot_ns();
        target += period;
        uint64_t missed = end > target ? (end - target) / period + 1 : 0;
        target += missed * period;
        printf("{\"event\":\"sample\",\"sequence\":%u,\"begin_ns\":%" PRIu64 ",\"end_ns\":%" PRIu64
               ",\"wall_ns\":%" PRIu64 ",\"wall_boot_end_ns\":%" PRIu64 ",\"missed_periods\":%" PRIu64 "}\n",
               sequence, begin, end, wall_ns, wall_boot_end, missed);
        if (fflush(stdout)) { failed = 1; break; }
        if (failed) break;
        struct timespec delay = {.tv_sec=(time_t)(target / 1000000000), .tv_nsec=(long)(target % 1000000000)};
        int rc;
        while (!stopping && (rc=clock_nanosleep(CLOCK_BOOTTIME, TIMER_ABSTIME, &delay, NULL)) != 0) {
            if (rc != EINTR) { failed = 1; break; }
        }
        if (failed) break;
    }
    printf("{\"event\":\"end\",\"boottime_ns\":%" PRIu64 ",\"samples\":%u,\"signalled\":%s,\"failed\":%s}\n",
           boot_ns(), sequence, stopping ? "true" : "false", failed ? "true" : "false");
    close(nl); close(uidmap); close(map);
    return fflush(stdout) || failed ? 1 : 0;
}
