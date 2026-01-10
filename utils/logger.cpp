#include "logger.h"

#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <cstdio>
#include <cstdarg>
#include <ctime>
#include <sys/types.h>
#include <cstdlib>

static int g_log_fd = -1;

/* Tunables */
static constexpr size_t LOG_BUF_SIZE = 64 * 1024;

static char   g_buf[LOG_BUF_SIZE];
static size_t g_pos = 0;

/* ---------- internals ---------- */

static inline void flush_internal()
{
    if (g_log_fd < 0 || g_pos == 0)
        return;

    ssize_t n = write(g_log_fd, g_buf, g_pos);
    (void)n;            // best effort
    g_pos = 0;
}

static inline void ensure_space(size_t need)
{
    if (need > LOG_BUF_SIZE)
        return; // drop oversized log

    if (g_pos + need > LOG_BUF_SIZE)
        flush_internal();
}

/* ---------- public API ---------- */

void log_init_file(const char* path)
{
    int fd = open(path,
                  O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC | O_NONBLOCK,
                  0644);
    if (fd < 0)
        return;

    g_log_fd = fd;
}

void log_init()
{
    const char* env = getenv("VPN_LOG_FILE");
    if (env && *env) {
        log_init_file(env);
        return;
    }

    int flags = fcntl(STDERR_FILENO, F_GETFL, 0);
    if (flags >= 0)
        fcntl(STDERR_FILENO, F_SETFL, flags | O_NONBLOCK);

    g_log_fd = STDERR_FILENO;
}

void log_shutdown()
{
    flush_internal();

    if (g_log_fd >= 0 && g_log_fd != STDERR_FILENO)
        close(g_log_fd);

    g_log_fd = -1;
}

void log_flush()
{
    flush_internal();
}

void log_write(LogLevel lvl, const char* fmt, ...)
{
    if (g_log_fd < 0)
        return;

    /* timestamp */
    char ts[32];
    time_t t = time(nullptr);
    struct tm tm;
    localtime_r(&t, &tm);

    int ts_len = snprintf(ts, sizeof(ts),
                          "%02d:%02d:%02d ",
                          tm.tm_hour, tm.tm_min, tm.tm_sec);

    const char* lvl_str =
        (lvl == LOG_ERROR) ? "[ERR] " :
        (lvl == LOG_WARN)  ? "[WRN] " :
        (lvl == LOG_INFO)  ? "[INF] " :
                             "[DBG] ";

    char msg[512];

    va_list ap;
    va_start(ap, fmt);
    int msg_len = vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    if (msg_len <= 0)
        return;

    size_t total =
        ts_len + strlen(lvl_str) + msg_len + 1;

    ensure_space(total);

    memcpy(g_buf + g_pos, ts, ts_len);
    g_pos += ts_len;

    size_t lvl_len = strlen(lvl_str);
    memcpy(g_buf + g_pos, lvl_str, lvl_len);
    g_pos += lvl_len;

    memcpy(g_buf + g_pos, msg, msg_len);
    g_pos += msg_len;

    g_buf[g_pos++] = '\n';
}
