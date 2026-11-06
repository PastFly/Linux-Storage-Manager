#define _GNU_SOURCE
#ifdef __linux__
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdbool.h>
#include <limits.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#ifndef CGROUP2_SUPER_MAGIC
#define CGROUP2_SUPER_MAGIC 0x63677270
#endif
#define MAX_LEASES 32
#define MAX_FDS (MAX_LEASES + 2)
#define CONTROL_FD 3

static void terminate_now(int code) { _exit(code); }

static int populated(int fd) {
    char buf[512];
    if (lseek(fd, 0, SEEK_SET) < 0) return -1;
    ssize_t n;
    do { n = read(fd, buf, sizeof(buf) - 1); } while (n < 0 && errno == EINTR);
    if (n <= 0) return -1;
    buf[n] = '\0';
    char *save = NULL;
    for (char *s = strtok_r(buf, "\n", &save); s; s = strtok_r(NULL, "\n", &save)) {
        if (!strcmp(s, "populated 0")) return 0;
        if (!strcmp(s, "populated 1")) return 1;
    }
    return -1;
}

static void kill_and_wait(int killfd, int eventsfd) {
    const char one = '1';
    for (;;) {
        ssize_t n = write(killfd, &one, 1);
        if (n == 1) break;
        if (n < 0 && errno == EINTR) continue;
        /* Fail closed: retain lease descriptors and retry, never report success. */
        struct timespec delay = { 0, 100000000 };
        nanosleep(&delay, NULL);
    }
    for (;;) {
        if (populated(eventsfd) == 0) return;
        struct timespec delay = { 0, 50000000 };
        nanosleep(&delay, NULL);
    }
}

static bool is_pidfd_for_peer(int fd, pid_t peer, bool *dead) {
    char path[64], link[128], contents[1024];
    int n = snprintf(path, sizeof(path), "/proc/self/fd/%d", fd);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    ssize_t len = readlink(path, link, sizeof(link) - 1);
    if (len <= 0) return false;
    link[len] = '\0';
    if (strcmp(link, "anon_inode:[pidfd]")) return false;
    n = snprintf(path, sizeof(path), "/proc/self/fdinfo/%d", fd);
    if (n <= 0 || (size_t)n >= sizeof(path)) return false;
    int info = open(path, O_RDONLY | O_CLOEXEC);
    if (info < 0) return false;
    ssize_t got;
    do { got = read(info, contents, sizeof(contents) - 1); } while (got < 0 && errno == EINTR);
    close(info);
    if (got <= 0) return false;
    contents[got] = '\0';
    char *save = NULL;
    for (char *line = strtok_r(contents, "\n", &save); line; line = strtok_r(NULL, "\n", &save)) {
        long value; char extra;
        if (sscanf(line, "Pid: %ld %c", &value, &extra) == 1) {
            if (value == -1) { *dead = true; return true; }
            *dead = false;
            return value == (long)peer;
        }
    }
    return false;
}

int main(int argc, char **argv) {
    if (argc != 2) return 2;
    char *end = NULL;
    errno = 0;
    long raw = strtol(argv[1], &end, 10);
    if (errno || !end || *end || raw < 3 || raw > INT_MAX) return 2;
    if ((int)raw != CONTROL_FD && dup2((int)raw, CONTROL_FD) != CONTROL_FD) return 2;
    if (fcntl(CONTROL_FD, F_SETFD, FD_CLOEXEC) < 0) return 2;
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 4U, UINT_MAX, 0U) < 0) return 2;
#else
    return 2;
#endif
    close(0); close(1); close(2);
    struct ucred peer;
    socklen_t peer_size = sizeof(peer);
    if (getsockopt(CONTROL_FD, SOL_SOCKET, SO_PEERCRED, &peer, &peer_size) < 0 ||
        peer_size != sizeof(peer) || peer.pid <= 0) terminate_now(3);

    uint32_t lease_count = 0;
    struct iovec iov = { .iov_base = &lease_count, .iov_len = sizeof(lease_count) };
    union { struct cmsghdr align; char buf[CMSG_SPACE(MAX_FDS * sizeof(int))]; } ancillary;
    memset(&ancillary, 0, sizeof(ancillary));
    struct msghdr msg = { .msg_iov = &iov, .msg_iovlen = 1,
                          .msg_control = ancillary.buf, .msg_controllen = sizeof(ancillary.buf) };
    ssize_t size;
    do { size = recvmsg(CONTROL_FD, &msg, MSG_CMSG_CLOEXEC); } while (size < 0 && errno == EINTR);
    if (size != (ssize_t)sizeof(lease_count) || (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC)) ||
        lease_count == 0 || lease_count > MAX_LEASES) terminate_now(3);
    struct cmsghdr *c = CMSG_FIRSTHDR(&msg);
    if (!c || c->cmsg_level != SOL_SOCKET || c->cmsg_type != SCM_RIGHTS ||
        c->cmsg_len != CMSG_LEN((lease_count + 2) * sizeof(int)) ||
        (CMSG_ALIGN(c->cmsg_len) <= msg.msg_controllen &&
         msg.msg_controllen - CMSG_ALIGN(c->cmsg_len) >= sizeof(struct cmsghdr)))
        terminate_now(3);
    int fds[MAX_FDS];
    memcpy(fds, CMSG_DATA(c), (lease_count + 2) * sizeof(int));
    int manager = fds[0], group = fds[1];
    struct stat st;
    struct statfs fs;
    bool manager_dead = false;
    if (!is_pidfd_for_peer(manager, peer.pid, &manager_dead) ||
        fstat(group, &st) < 0 || !S_ISDIR(st.st_mode) ||
        fstatfs(group, &fs) < 0 || (unsigned long)fs.f_type != CGROUP2_SUPER_MAGIC)
        terminate_now(4);
    int events = openat(group, "cgroup.events", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    int killfd = openat(group, "cgroup.kill", O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (events < 0 || killfd < 0) terminate_now(4);
    /* Empty cgroup at handshake proves observer is not within its subtree. */
    if (populated(events) != 0) terminate_now(4);
    for (uint32_t i = 0; i < lease_count; i++) {
        if (fcntl(fds[i + 2], F_GETLEASE) != F_RDLCK) terminate_now(4);
    }
    if (manager_dead || send(CONTROL_FD, "R", 1, MSG_NOSIGNAL) != 1) {
        kill_and_wait(killfd, events);
        terminate_now(5);
    }
    struct pollfd p[2] = {
        { .fd = manager, .events = POLLIN },
        { .fd = CONTROL_FD, .events = POLLIN }
    };
    for (;;) {
        int result;
        do { result = poll(p, 2, -1); } while (result < 0 && errno == EINTR);
        if (result < 0 || p[0].revents || (p[1].revents & (POLLERR | POLLHUP | POLLNVAL))) break;
        if (p[1].revents & POLLIN) {
            char command = 0;
            ssize_t r = recv(CONTROL_FD, &command, 1, 0);
            if (r == 1 && command == 'Q' && populated(events) == 0) {
                /* Protocol: manager guarantees no further spawn after Q. */
                if (send(CONTROL_FD, "Q", 1, MSG_NOSIGNAL) == 1) terminate_now(0);
            }
            break;
        }
    }
    kill_and_wait(killfd, events);
    terminate_now(0);
}
#else
#include <stdio.h>
int main(void) { fputs("This observer requires Linux.\n", stderr); return 2; }
#endif
