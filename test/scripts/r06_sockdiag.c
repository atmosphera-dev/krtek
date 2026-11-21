/* Read-only r06 socket snapshots. Build/run only in an assigned guest.
 *
 * This samples an existing socket; it does not prebind/replace Java Socket,
 * consume SO_ERROR (which clears it), or infer a syscall errno. An absent
 * sample is not proof that a short-lived socket never existed. Join BOOTTIME
 * timestamps/inode/cookie to the separate syscall and capture observations.
 */
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/inet_diag.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sock_diag.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static uint64_t boot_ns(void) {
    struct timespec value;
    if (clock_gettime(CLOCK_BOOTTIME, &value)) {
        perror("clock_gettime");
        exit(1);
    }
    return (uint64_t)value.tv_sec * UINT64_C(1000000000) + (uint64_t)value.tv_nsec;
}

static unsigned number(const char *text, unsigned maximum) {
    char *end;
    errno = 0;
    unsigned long result = strtoul(text, &end, 10);
    if (errno || !*text || *end || result > maximum) {
        fprintf(stderr, "Invalid numeric argument\n");
        exit(2);
    }
    return (unsigned)result;
}

static int fd_rows(unsigned pid, uint32_t inode, uint32_t sequence) {
    char directory[64];
    snprintf(directory, sizeof(directory), "/proc/%u/fd", pid);
    DIR *entries = opendir(directory);
    if (!entries) return -1;
    struct dirent *entry;
    int matched = 0;
    while ((entry = readdir(entries))) {
        char *end;
        errno = 0;
        unsigned long fd = strtoul(entry->d_name, &end, 10);
        if (errno || !*entry->d_name || *end || fd > INT_MAX) continue;
        char path[96], link[64], expected[64];
        snprintf(path, sizeof(path), "%s/%lu", directory, fd);
        ssize_t size = readlink(path, link, sizeof(link) - 1);
        if (size < 0) continue; /* Racing close is explicitly allowed in a snapshot. */
        link[size] = 0;
        snprintf(expected, sizeof(expected), "socket:[%" PRIu32 "]", inode);
        if (strcmp(link, expected)) continue;
        printf("{\"event\":\"fd\",\"sequence\":%" PRIu32 ",\"boottime_ns\":%" PRIu64
               ",\"pid\":%u,\"fd\":%lu,\"inode\":%" PRIu32 "}\n",
               sequence, boot_ns(), pid, fd, inode);
        matched++;
    }
    closedir(entries);
    return matched;
}

static int dump_family(int fd, int family, int protocol, const unsigned char *wanted,
                       unsigned port, unsigned pid, uint32_t sequence, unsigned *count) {
    struct { struct nlmsghdr header; struct inet_diag_req_v2 request; } request = {0};
    request.header.nlmsg_len = sizeof(request);
    request.header.nlmsg_type = SOCK_DIAG_BY_FAMILY;
    request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    request.header.nlmsg_seq = sequence;
    request.request.sdiag_family = family;
    request.request.sdiag_protocol = protocol;
    request.request.idiag_states = UINT32_MAX;
    struct sockaddr_nl kernel = {.nl_family = AF_NETLINK};
    if (sendto(fd, &request, sizeof(request), 0, (struct sockaddr *)&kernel, sizeof(kernel)) != sizeof(request)) return -1;
    for (;;) {
        /* UAPI structs require alignment, unlike a bare byte array. */
        union { struct nlmsghdr align; unsigned char bytes[65536]; } buffer;
        struct sockaddr_nl sender = {0};
        struct iovec iov = {.iov_base = buffer.bytes, .iov_len = sizeof(buffer.bytes)};
        struct msghdr message = {.msg_name = &sender, .msg_namelen = sizeof(sender),
                                .msg_iov = &iov, .msg_iovlen = 1};
        ssize_t size = recvmsg(fd, &message, 0);
        if (size <= 0 || message.msg_flags & (MSG_TRUNC | MSG_CTRUNC) || sender.nl_pid != 0) return -1;
        unsigned remaining = (unsigned)size;
        for (struct nlmsghdr *header = (struct nlmsghdr *)buffer.bytes;
             NLMSG_OK(header, remaining); header = NLMSG_NEXT(header, remaining)) {
            if (header->nlmsg_seq != sequence || header->nlmsg_flags & NLM_F_DUMP_INTR) return -1;
            if (header->nlmsg_type == NLMSG_DONE) {
                if (header->nlmsg_len >= NLMSG_LENGTH(sizeof(int))) {
                    int result;
                    memcpy(&result, NLMSG_DATA(header), sizeof(result));
                    if (result) return -1;
                }
                return 0;
            }
            if (header->nlmsg_type != SOCK_DIAG_BY_FAMILY ||
                header->nlmsg_len < NLMSG_LENGTH(sizeof(struct inet_diag_msg))) return -1;
            struct inet_diag_msg *value = NLMSG_DATA(header);
            if (value->idiag_family != family || ntohs(value->id.idiag_dport) != port ||
                memcmp(value->id.idiag_dst, wanted, family == AF_INET ? 4 : 16)) continue;
            int length = header->nlmsg_len - NLMSG_LENGTH(sizeof(*value));
            uint32_t mark = 0;
            int have_mark = 0;
            for (struct rtattr *attribute = (struct rtattr *)((unsigned char *)value + NLMSG_ALIGN(sizeof(*value)));
                 RTA_OK(attribute, length); attribute = RTA_NEXT(attribute, length)) {
                if (attribute->rta_type == INET_DIAG_MARK && RTA_PAYLOAD(attribute) == sizeof(mark)) {
                    memcpy(&mark, RTA_DATA(attribute), sizeof(mark));
                    have_mark = 1;
                }
            }
            if (length) return -1;
            char source[INET6_ADDRSTRLEN], destination[INET6_ADDRSTRLEN];
            if (!inet_ntop(family, value->id.idiag_src, source, sizeof(source)) ||
                !inet_ntop(family, value->id.idiag_dst, destination, sizeof(destination))) return -1;
            int matches = fd_rows(pid, value->idiag_inode, sequence);
            printf("{\"event\":\"socket\",\"sequence\":%" PRIu32 ",\"boottime_ns\":%" PRIu64
                   ",\"family\":%d,\"protocol\":%d,\"state\":%u,\"source\":\"%s\",\"destination\":\"%s\","
                   "\"source_port\":%u,\"destination_port\":%u,\"uid\":%u,\"inode\":%u,"
                   "\"cookie\":[%" PRIu32 ",%" PRIu32 "],\"ifindex\":%u,\"mark\":%u,\"mark_present\":%s,"
                   "\"fd_scan_available\":%s,\"fd_matches\":%d}\n",
                   sequence, boot_ns(), family == AF_INET ? 4 : 6, protocol, value->idiag_state,
                   source, destination, ntohs(value->id.idiag_sport), ntohs(value->id.idiag_dport),
                   value->idiag_uid, value->idiag_inode, value->id.idiag_cookie[0], value->id.idiag_cookie[1],
                   value->id.idiag_if, mark, have_mark ? "true" : "false", matches < 0 ? "false" : "true", matches);
            (*count)++;
        }
        if (remaining) return -1;
    }
}

static int snapshot(int fd, int family, int protocol, const unsigned char *wanted,
                    unsigned port, unsigned pid, uint32_t sequence) {
    unsigned count = 0;
    printf("{\"event\":\"snapshot_begin\",\"sequence\":%" PRIu32
           ",\"boottime_ns\":%" PRIu64 "}\n", sequence, boot_ns());
    if (dump_family(fd, family, protocol, wanted, port, pid, sequence, &count)) return -1;
    if (family == AF_INET) {
        unsigned char mapped[16] = {0};
        mapped[10] = mapped[11] = 0xff;
        memcpy(mapped + 12, wanted, 4);
        if (dump_family(fd, AF_INET6, protocol, mapped, port, pid, sequence, &count)) return -1;
    }
    printf("{\"event\":\"snapshot_end\",\"sequence\":%" PRIu32
           ",\"boottime_ns\":%" PRIu64 ",\"sockets\":%u,\"complete\":true}\n",
           sequence, boot_ns(), count);
    return fflush(stdout) ? -1 : 0;
}

int main(int argc, char **argv) {
    if (argc != 7) {
        fprintf(stderr, "Usage: r06_sockdiag tcp|udp numeric-destination port pid snapshots interval-ms\n");
        return 2;
    }
    int protocol = !strcmp(argv[1], "tcp") ? IPPROTO_TCP : !strcmp(argv[1], "udp") ? IPPROTO_UDP : 0;
    int family = strchr(argv[2], ':') ? AF_INET6 : AF_INET;
    unsigned char wanted[16] = {0};
    unsigned port = number(argv[3], UINT16_MAX), pid = number(argv[4], INT_MAX);
    unsigned count = number(argv[5], UINT32_MAX - 1), interval_ms = number(argv[6], INT_MAX);
    if (!protocol || !port || !pid || !count || inet_pton(family, argv[2], wanted) != 1) return 2;
    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_SOCK_DIAG);
    if (fd < 0) { perror("socket"); return 1; }
    struct timeval timeout = {.tv_sec = 5};
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout))) { close(fd); return 1; }
    for (uint32_t sequence = 1; sequence <= count; sequence++) {
        if (snapshot(fd, family, protocol, wanted, port, pid, sequence)) {
            fprintf(stderr, "Incomplete socket dump at sequence %" PRIu32 ", errno=%d\n", sequence, errno);
            close(fd);
            return 1;
        }
        if (sequence < count) {
            struct timespec delay = {.tv_sec = interval_ms / 1000, .tv_nsec = (interval_ms % 1000) * 1000000L};
            while (nanosleep(&delay, &delay)) {
                if (errno != EINTR) { close(fd); return 1; }
            }
        }
    }
    close(fd);
    return 0;
}
