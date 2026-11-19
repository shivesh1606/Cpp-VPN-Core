// Logger: line format, explicit flush, and bounded lines.
//
// vsnprintf returns the length the message WOULD have had, not what fit into the 512-byte
// message buffer. log_write used that value as the copy length, so a message longer than 511
// characters read past the buffer, and one longer than the 64 KB line buffer was copied past
// its end. A realistic trigger is a long auth.revocation_url (e.g. a signed storage URL), which
// is logged at startup.
#include <gtest/gtest.h>

#include <unistd.h>

#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "utils/logger.h"

namespace
{

constexpr size_t kTimeLen = 9;   // "HH:MM:SS "
constexpr size_t kLevelLen = 6;  // "[INF] "
constexpr size_t kMaxMsgLen = 511; // message buffer is 512 bytes including the terminator

class LoggerTest : public testing::Test
{
protected:
    void SetUp() override
    {
        char tmpl[] = "/tmp/cppvpn_log_XXXXXX";
        const int fd = mkstemp(tmpl);
        ASSERT_GE(fd, 0);
        close(fd);
        path_ = tmpl;
        log_init_file(path_.c_str());
    }
    void TearDown() override
    {
        log_shutdown(); // back to "no log fd", so LOG() in other tests stays a no-op
        unlink(path_.c_str());
    }
    std::vector<std::string> lines()
    {
        log_flush();
        std::ifstream f(path_, std::ios::binary);
        std::vector<std::string> out;
        for (std::string l; std::getline(f, l);)
            out.push_back(l);
        return out;
    }
    std::string path_;
};

std::string message(const std::string &line)
{
    return line.size() >= kTimeLen + kLevelLen ? line.substr(kTimeLen + kLevelLen) : "";
}

} // namespace

TEST_F(LoggerTest, LinesReachTheFileOnFlush)
{
    LOG(LOG_INFO, "hello %d", 42);
    LOG(LOG_WARN, "second");
    const auto l = lines();
    ASSERT_EQ(l.size(), 2u);
    EXPECT_EQ(l[0].substr(kTimeLen, kLevelLen), "[INF] ");
    EXPECT_EQ(message(l[0]), "hello 42");
    EXPECT_EQ(l[1].substr(kTimeLen, kLevelLen), "[WRN] ");
    EXPECT_EQ(message(l[1]), "second");
}

TEST_F(LoggerTest, LongMessageIsTruncatedToTheBufferNotReadPastIt)
{
    const std::string url = "https://storage.example/revocations.bin?" + std::string(2000, 'x');
    LOG(LOG_INFO, "Revocations: polling %s every %d s", url.c_str(), 300);
    const auto l = lines();
    ASSERT_EQ(l.size(), 1u);
    const std::string full = "Revocations: polling " + url + " every 300 s";
    EXPECT_EQ(message(l[0]), full.substr(0, kMaxMsgLen));
}

TEST_F(LoggerTest, MessageLongerThanTheLineBufferDoesNotOverflowIt)
{
    const std::string huge(200000, 'y'); // > 64 KB line buffer
    LOG(LOG_WARN, "%s", huge.c_str());
    LOG(LOG_INFO, "after");
    const auto l = lines();
    ASSERT_EQ(l.size(), 2u);
    EXPECT_EQ(message(l[0]), std::string(kMaxMsgLen, 'y'));
    EXPECT_EQ(message(l[1]), "after");
}

TEST_F(LoggerTest, ExactlyFullMessageIsKept)
{
    const std::string m(kMaxMsgLen, 'z');
    LOG(LOG_INFO, "%s", m.c_str());
    const auto l = lines();
    ASSERT_EQ(l.size(), 1u);
    EXPECT_EQ(message(l[0]), m);
}
