// perf_hook_full.c
#define _GNU_SOURCE
#include <dlfcn.h>
#include <sys/socket.h>
#include <time.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/uio.h>
#include <netinet/in.h>

typedef ssize_t (*orig_recvfrom_type)(int, void *, size_t, int, struct sockaddr *, socklen_t *);
typedef ssize_t (*orig_write_type)(int, const void *, size_t *);

#define MAX_BATCH 16
#define MAX_PACKET_SIZE 2000

// ---------------- recvfrom hook ----------------
ssize_t recvfrom(int sockfd, void *buf, size_t len, int flags,
                 struct sockaddr *src_addr, socklen_t *addrlen)
{
    static orig_recvfrom_type orig_recvfrom = NULL;
    if (!orig_recvfrom) {
        orig_recvfrom = (orig_recvfrom_type)dlsym(RTLD_NEXT, "recvfrom");
        if (!orig_recvfrom) return -1;
    }

    struct mmsghdr msgs[MAX_BATCH];
    struct iovec iovs[MAX_BATCH];
    struct sockaddr_in addrs[MAX_BATCH];
    char temp_buffers[MAX_BATCH][MAX_PACKET_SIZE];

    for (int i = 0; i < MAX_BATCH; i++) {
        iovs[i].iov_base = temp_buffers[i];
        iovs[i].iov_len = MAX_PACKET_SIZE;
        memset(&addrs[i], 0, sizeof(addrs[i]));

        msgs[i].msg_hdr.msg_iov = &iovs[i];
        msgs[i].msg_hdr.msg_iovlen = 1;
        msgs[i].msg_hdr.msg_name = &addrs[i];
        msgs[i].msg_hdr.msg_namelen = sizeof(addrs[i]);
        msgs[i].msg_hdr.msg_control = NULL;
        msgs[i].msg_hdr.msg_controllen = 0;
        msgs[i].msg_hdr.msg_flags = 0;
        msgs[i].msg_len = 0;
    }

    int ret = recvmmsg(sockfd, msgs, MAX_BATCH, MSG_DONTWAIT, NULL);
    if (ret > 0) {
        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);

        for (int i = 0; i < ret; i++) {
            printf("[HOOK][UDP] packet %d: %u bytes ts=%ld.%09ld\n",
                   i, (unsigned)msgs[i].msg_len, ts.tv_sec, ts.tv_nsec);
        }

        // Copy first packet to your buffer for existing code
        if (msgs[0].msg_len > 0) {
            memcpy(buf, temp_buffers[0], msgs[0].msg_len);
            if (src_addr && addrlen) {
                memcpy(src_addr, &addrs[0], sizeof(struct sockaddr_in));
                *addrlen = sizeof(struct sockaddr_in);
            }
            return msgs[0].msg_len;
        }
        return 0;
    }
    else if (ret == 0 || (ret < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))) {
        return orig_recvfrom(sockfd, buf, len, flags, src_addr, addrlen);
    } else {
        return ret;
    }
}

// ---------------- write hook ----------------
ssize_t write(int fd, const void *buf, size_t count)
{
    static orig_write_type orig_write = NULL;
    if (!orig_write) {
        orig_write = (orig_write_type)dlsym(RTLD_NEXT, "write");
        if (!orig_write) return -1;
    }

    // Only batch TUN writes, skip others
    if (fd >= 0) { // naive: assume your TUN fd is > 0, adjust if needed
        static char batch_buf[MAX_BATCH * MAX_PACKET_SIZE];
        static size_t batch_offset = 0;

        if (count > MAX_PACKET_SIZE) count = MAX_PACKET_SIZE;
        memcpy(batch_buf + batch_offset, buf, count);
        batch_offset += count;

        // Flush if batch full
        if (batch_offset >= sizeof(batch_buf)) {
            ssize_t ret = orig_write(fd, batch_buf, batch_offset);
            batch_offset = 0;
            return ret;
        }

        // For simplicity, flush immediately (could be timed)
        ssize_t ret = orig_write(fd, batch_buf, batch_offset);
        batch_offset = 0;
        return ret;
    }

    return orig_write(fd, buf, count);
}
