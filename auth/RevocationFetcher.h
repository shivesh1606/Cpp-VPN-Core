// RevocationFetcher.h - periodic revocation-list download off the packet loop (design 03 section 6).
//
// A background thread calls `fetch` every `interval` (first call immediately) and leaves the
// bytes in a mailbox when they differ from the previous download. The packet loop calls take()
// once a second; verification and applying the list happen there, single-threaded, so the
// session table needs no locking. A failed fetch only logs; the node keeps its last good list.
//
// curlFetch() runs the system `curl` (posix_spawnp, no shell) with https-only protocols, a time
// limit and a size limit.
#ifndef AUTH_REVOCATIONFETCHER_H
#define AUTH_REVOCATIONFETCHER_H

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace auth
{

using FetchFn = std::function<bool(std::vector<uint8_t> &bytes, std::string &error)>;

// Downloads `url` (https only) with the curl binary. `allow_file_scheme` is for tests.
bool curlFetch(const std::string &url, std::vector<uint8_t> &bytes, std::string &error,
               bool allow_file_scheme = false);

class RevocationFetcher
{
public:
    RevocationFetcher(FetchFn fetch, std::chrono::milliseconds interval);
    ~RevocationFetcher(); // stops and joins the thread

    // New bytes since the last take(), if any. Non-blocking.
    bool take(std::vector<uint8_t> &bytes);
    // Last fetch error ("" after a success), for logging.
    std::string lastError();
    uint64_t attempts();

private:
    void run();

    FetchFn fetch_;
    std::chrono::milliseconds interval_;
    std::mutex mu_;
    std::condition_variable cv_;
    bool stop_ = false, has_new_ = false;
    std::vector<uint8_t> mailbox_, last_;
    std::string error_;
    uint64_t attempts_ = 0;
    std::thread thread_;
};

} // namespace auth

#endif // AUTH_REVOCATIONFETCHER_H
