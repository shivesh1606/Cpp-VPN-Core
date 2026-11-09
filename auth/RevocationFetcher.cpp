#include "auth/RevocationFetcher.h"

#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>

#include "config/Ini.h"

extern char **environ;

namespace auth
{

bool curlFetch(const std::string &url, std::vector<uint8_t> &bytes, std::string &error, bool allow_file_scheme)
{
    const bool https = url.rfind("https://", 0) == 0;
    if (!https && !(allow_file_scheme && url.rfind("file://", 0) == 0))
    {
        error = "revocation_url must be https://";
        return false;
    }
    char tmpl[] = "/tmp/cppvpn_revocations_XXXXXX";
    const int fd = mkstemp(tmpl);
    if (fd < 0)
    {
        error = "mkstemp failed";
        return false;
    }
    close(fd);
    const std::string protos = https ? "=https" : "=file";
    // -f: fail on HTTP errors, -sS: quiet but show errors, size and time limits, no redirects to
    // other protocols. The URL is passed as one argv element (no shell).
    const char *argv[] = {"curl", "-fsS", "--max-time", "20", "--max-filesize", "2000000",
                          "--proto", protos.c_str(), "--proto-redir", protos.c_str(), "-L",
                          "-o", tmpl, url.c_str(), nullptr};
    pid_t pid = 0;
    if (posix_spawnp(&pid, "curl", nullptr, nullptr, const_cast<char *const *>(argv), environ) != 0)
    {
        unlink(tmpl);
        error = "cannot run curl (install it: apt-get install curl)";
        return false;
    }
    int status = 0;
    while (waitpid(pid, &status, 0) < 0 && errno == EINTR)
    {
    }
    std::string text;
    const bool ok = WIFEXITED(status) && WEXITSTATUS(status) == 0 && config::readTextFile(tmpl, text, error);
    unlink(tmpl);
    if (!ok)
    {
        if (error.empty())
            error = "curl failed (exit " + std::to_string(WIFEXITED(status) ? WEXITSTATUS(status) : -1) + ")";
        return false;
    }
    bytes.assign(text.begin(), text.end());
    return true;
}

RevocationFetcher::RevocationFetcher(FetchFn fetch, std::chrono::milliseconds interval)
    : fetch_(std::move(fetch)), interval_(interval), thread_([this] { run(); })
{
}

RevocationFetcher::~RevocationFetcher()
{
    {
        std::lock_guard<std::mutex> lk(mu_);
        stop_ = true;
    }
    cv_.notify_all();
    thread_.join();
}

void RevocationFetcher::run()
{
    std::unique_lock<std::mutex> lk(mu_);
    while (!stop_)
    {
        lk.unlock();
        std::vector<uint8_t> bytes;
        std::string err;
        const bool ok = fetch_(bytes, err); // outside the lock: may take seconds
        lk.lock();
        attempts_++;
        if (ok)
        {
            error_.clear();
            if (bytes != last_)
            {
                last_ = bytes;
                mailbox_ = std::move(bytes);
                has_new_ = true;
            }
        }
        else
            error_ = err.empty() ? "fetch failed" : err;
        cv_.wait_for(lk, interval_, [this] { return stop_; });
    }
}

bool RevocationFetcher::take(std::vector<uint8_t> &bytes)
{
    std::lock_guard<std::mutex> lk(mu_);
    if (!has_new_)
        return false;
    bytes = std::move(mailbox_);
    mailbox_.clear();
    has_new_ = false;
    return true;
}

std::string RevocationFetcher::lastError()
{
    std::lock_guard<std::mutex> lk(mu_);
    return error_;
}

uint64_t RevocationFetcher::attempts()
{
    std::lock_guard<std::mutex> lk(mu_);
    return attempts_;
}

} // namespace auth
