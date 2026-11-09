// RevocationFetcher (design 03 section 6): background fetch, mailbox, no duplicates, errors kept.
#include <gtest/gtest.h>

#include <unistd.h>

#include <atomic>
#include <fstream>
#include <thread>

#include "auth/RevocationFetcher.h"

using namespace auth;
using namespace std::chrono_literals;

namespace
{
template <class F>
bool waitFor(F cond)
{
    for (int i = 0; i < 300; i++, std::this_thread::sleep_for(10ms))
        if (cond())
            return true;
    return false;
}
} // namespace

TEST(RevocationFetcher, DeliversNewBytesOnceAndKeepsPolling)
{
    std::atomic<int> calls{0};
    std::atomic<int> version{1};
    RevocationFetcher f(
        [&](std::vector<uint8_t> &b, std::string &) {
            calls++;
            b.assign(4, uint8_t(version.load()));
            return true;
        },
        20ms);
    std::vector<uint8_t> got;
    ASSERT_TRUE(waitFor([&] { return f.take(got); })) << "first fetch happens at once";
    EXPECT_EQ(got, std::vector<uint8_t>(4, 1));
    ASSERT_TRUE(waitFor([&] { return calls >= 4; }));
    EXPECT_FALSE(f.take(got)) << "unchanged bytes must not be delivered again";
    version = 2;
    ASSERT_TRUE(waitFor([&] { return f.take(got); }));
    EXPECT_EQ(got, std::vector<uint8_t>(4, 2));
    EXPECT_EQ(f.lastError(), "");
}

TEST(RevocationFetcher, FailuresAreReportedAndDoNotBlockShutdown)
{
    RevocationFetcher f(
        [](std::vector<uint8_t> &, std::string &e) {
            e = "network down";
            return false;
        },
        std::chrono::hours(1)); // destructor must wake the thread, not wait an hour
    ASSERT_TRUE(waitFor([&] { return f.attempts() >= 1; }));
    EXPECT_EQ(f.lastError(), "network down");
    std::vector<uint8_t> got;
    EXPECT_FALSE(f.take(got));
}

TEST(CurlFetch, RejectsNonHttpsAndReadsFileUrlsInTests)
{
    std::vector<uint8_t> b;
    std::string err;
    EXPECT_FALSE(curlFetch("http://example.org/r.bin", b, err));
    EXPECT_EQ(err, "revocation_url must be https://");
    if (system("command -v curl >/dev/null 2>&1") != 0)
        GTEST_SKIP() << "curl not installed";
    char tmpl[] = "/tmp/cppvpn_fetch_XXXXXX";
    const int fd = mkstemp(tmpl);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(write(fd, "\x01\x02\x03", 3), 3);
    close(fd);
    ASSERT_TRUE(curlFetch(std::string("file://") + tmpl, b, err, true)) << err;
    EXPECT_EQ(b, (std::vector<uint8_t>{1, 2, 3}));
    EXPECT_FALSE(curlFetch(std::string("file://") + tmpl + ".missing", b, err, true));
    unlink(tmpl);
}
