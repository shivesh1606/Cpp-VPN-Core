// crypto_bench - per-packet cost of every registered cipher backend (design doc 01, section 5).
//
// Runs seal / open / open-of-a-forged-packet through the real SessionLock objects that the
// server uses (one virtual call per packet, 14-byte AAD = v2 header size, counter nonce), so a
// new backend is benchmarked as soon as it is registered in CipherRegistry.
//
// Usage: crypto_bench [--sizes 64,512,1400] [--count 1000000] [--runs 3] [--filter TEXT] [--csv]
//                     [--no-vzeroupper]
// Pin to one core for stable numbers: taskset -c 2 ./crypto_bench
// Results and method: experiments/002-crypto-bench-backends/
#include <sodium.h>
#include <sys/utsname.h>
#include <time.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <string>
#include <vector>

#include "crypto/CipherRegistry.h"
#include "crypto/backends/SodiumAead.h"
#if CPPVPN_WITH_OPENSSL
#include "crypto/backends/OpenSslAead.h"
#endif
#include "crypto/backends/VectorState.h"

#if defined(__x86_64__) || defined(__i386__)
#include <x86intrin.h>
static inline uint64_t tsc() { return __rdtsc(); }
static constexpr bool kHaveTsc = true;
#else
static inline uint64_t tsc() { return 0; }
static constexpr bool kHaveTsc = false;
#endif

// Before each row: clear dirty upper vector state left by the previous backend, so a row's
// result does not depend on which backend ran before it (experiment 002, VectorState.h).
using crypto::clearUpperVectorState;

#ifndef CPPVPN_BUILD_FLAGS
#define CPPVPN_BUILD_FLAGS "?"
#endif
#ifndef CPPVPN_BUILD_TYPE
#define CPPVPN_BUILD_TYPE "?"
#endif

namespace
{

volatile uint8_t g_sink;

uint64_t nowNs()
{
    timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return static_cast<uint64_t>(t.tv_sec) * 1000000000ull + static_cast<uint64_t>(t.tv_nsec);
}

struct Opts
{
    std::vector<size_t> sizes{64, 512, 1400};
    long count = 1000000;
    int runs = 3;
    std::string filter;
    bool csv = false;
    bool clear_upper = true; // --no-vzeroupper reproduces cross-backend interference
};

struct Result
{
    double ns = 0, cyc = 0, spread = 0; // median per op; (max - min) / median over runs
};

// Runs `body(i)` count/10 times as warm-up, then `runs` timed rounds of `count` calls.
template <class Body>
Result measure(long count, int runs, bool clear_upper, Body &&body)
{
    if (clear_upper)
        clearUpperVectorState();
    for (long i = 0; i < count / 10; i++)
        body(i);
    std::vector<double> ns, cyc;
    for (int r = 0; r < runs; r++)
    {
        const uint64_t t0 = nowNs(), c0 = tsc();
        for (long i = 0; i < count; i++)
            body(i);
        const uint64_t c1 = tsc(), t1 = nowNs();
        ns.push_back(static_cast<double>(t1 - t0) / count);
        cyc.push_back(static_cast<double>(c1 - c0) / count);
    }
    auto median = [](std::vector<double> v) {
        std::sort(v.begin(), v.end());
        return v[v.size() / 2];
    };
    Result res;
    res.ns = median(ns);
    res.cyc = median(cyc);
    const auto mm = std::minmax_element(ns.begin(), ns.end());
    res.spread = res.ns > 0 ? (*mm.second - *mm.first) / res.ns : 0;
    return res;
}

std::string cpuModel()
{
    std::ifstream f("/proc/cpuinfo");
    std::string line;
    while (std::getline(f, line))
        if (line.rfind("model name", 0) == 0 || line.rfind("Model", 0) == 0)
            return line.substr(line.find(':') + 2);
    return "unknown (see lscpu)";
}

bool parseArgs(int argc, char **argv, Opts &o)
{
    for (int i = 1; i < argc; i++)
    {
        const std::string a = argv[i];
        const bool has_val = i + 1 < argc;
        if (a == "--sizes" && has_val)
        {
            o.sizes.clear();
            std::string s = argv[++i];
            for (size_t p = 0; p <= s.size();)
            {
                size_t q = s.find(',', p);
                if (q == std::string::npos)
                    q = s.size();
                const long v = std::atol(s.substr(p, q - p).c_str());
                if (v < 0 || v > 65000)
                    return false;
                o.sizes.push_back(static_cast<size_t>(v));
                p = q + 1;
            }
        }
        else if (a == "--count" && has_val)
            o.count = std::atol(argv[++i]);
        else if (a == "--runs" && has_val)
            o.runs = std::atoi(argv[++i]);
        else if (a == "--filter" && has_val)
            o.filter = argv[++i];
        else if (a == "--csv")
            o.csv = true;
        else if (a == "--no-vzeroupper")
            o.clear_upper = false;
        else
            return false;
    }
    return o.count > 0 && o.runs > 0 && !o.sizes.empty();
}

void printHeader(const Opts &o)
{
    utsname u{};
    uname(&u);
    char date[32];
    const time_t now = time(nullptr);
    strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%S%z", localtime(&now));
    std::printf("# crypto_bench (design 01 section 5)\n");
    std::printf("# date:      %s\n", date);
    std::printf("# host:      %s %s %s\n", u.nodename, u.release, u.machine);
    std::printf("# cpu:       %s\n", cpuModel().c_str());
    std::printf("# compiler:  %s, build type '%s', flags '%s'\n", __VERSION__, CPPVPN_BUILD_TYPE,
                CPPVPN_BUILD_FLAGS);
    std::printf("# libsodium: %s (hardware AES-256-GCM: %s)\n", sodium_version_string(),
                crypto::sodiumAes256GcmAvailable() ? "yes" : "no");
#if CPPVPN_WITH_OPENSSL
    std::printf("# openssl:   %s\n", crypto::openSslVersion());
#else
    std::printf("# openssl:   not built (-DWITH_OPENSSL=ON)\n");
#endif
    std::printf("# method:    %ld ops x %d runs per row after %ld warm-up ops; median reported; "
                "spread = (max-min)/median\n",
                o.count, o.runs, o.count / 10);
    std::printf("# isolation: vzeroupper before each row: %s\n",
                o.clear_upper ? "yes" : "no (--no-vzeroupper)");
    std::printf("# timing:    CLOCK_MONOTONIC ns%s; AAD 14 B; counter nonce\n",
                kHaveTsc ? ", TSC reference cycles (not core cycles)" : "; no TSC on this arch");
}

} // namespace

int main(int argc, char **argv)
{
    Opts o;
    if (!parseArgs(argc, argv, o))
    {
        std::fprintf(stderr, "usage: %s [--sizes 64,512,1400] [--count N] [--runs R] "
                             "[--filter TEXT] [--csv] [--no-vzeroupper]\n",
                     argv[0]);
        return 2;
    }
    const auto &backends = crypto::CipherRegistry::instance().all();
    printHeader(o);
    std::printf("# backends: ");
    for (const auto &b : backends)
        std::printf(" %s/%s", b->algorithmName(), b->implName());
    std::printf("\n\n");

    if (o.csv)
        std::printf("backend,op,size,ns_per_op,tsc_cyc_per_op,tsc_cyc_per_byte,gbit_per_s,spread\n");
    else
        std::printf("%-28s %-12s %6s %10s %10s %8s %8s %7s\n", "backend", "op", "size", "ns/op",
                    "cyc/op", "cyc/B", "Gbit/s", "spread");

    const size_t max_size = *std::max_element(o.sizes.begin(), o.sizes.end());
    std::vector<uint8_t> in(max_size), ct(max_size + 64), forged(max_size + 64), back(max_size + 64);
    uint8_t key[crypto::kKeyBytes], aad[14] = {0x20, 4};
    randombytes_buf(key, sizeof(key));
    randombytes_buf(in.data(), in.size());

    int failures = 0;
    for (const auto &b : backends)
    {
        const std::string name = std::string(b->algorithmName()) + "/" + b->implName();
        if (!o.filter.empty() && name.find(o.filter) == std::string::npos)
            continue;
        auto lock = b->newLock(key);
        const size_t ov = lock->overhead();
        for (size_t len : o.sizes)
        {
            auto row = [&](const char *op, const Result &r) {
                const double cpb = len ? r.cyc / len : 0;
                const double gbps = r.ns > 0 ? len * 8.0 / r.ns : 0;
                if (o.csv)
                    std::printf("%s,%s,%zu,%.1f,%.0f,%.2f,%.2f,%.3f\n", name.c_str(), op, len,
                                r.ns, r.cyc, cpb, gbps, r.spread);
                else
                    std::printf("%-28s %-12s %6zu %10.1f %10.0f %8.2f %8.2f %6.1f%%\n",
                                name.c_str(), op, len, r.ns, r.cyc, cpb, gbps, r.spread * 100);
                std::fflush(stdout);
            };

            uint64_t ctr = 0;
            row("seal", measure(o.count, o.runs, o.clear_upper, [&](long) {
                    lock->seal(ctr++, aad, sizeof(aad), in.data(), len, ct.data());
                    g_sink = g_sink ^ ct[0];
                }));

            lock->seal(7, aad, sizeof(aad), in.data(), len, ct.data());
            long bad = 0;
            row("open", measure(o.count, o.runs, o.clear_upper, [&](long) {
                    bad += !lock->open(7, aad, sizeof(aad), ct.data(), len + ov, back.data());
                    g_sink = g_sink ^ back[0];
                }));
            if (bad)
            {
                std::fprintf(stderr, "ERROR: %s open() failed %ld times on valid input\n",
                             name.c_str(), bad);
                failures++;
            }

            if (ov == 0)
                continue; // no integrity: a forged packet cannot be detected (xor)
            std::memcpy(forged.data(), ct.data(), len + ov);
            forged[len + ov - 1] ^= 1; // corrupt the tag
            long accepted = 0;
            row("open-forged", measure(o.count, o.runs, o.clear_upper, [&](long) {
                    accepted += lock->open(7, aad, sizeof(aad), forged.data(), len + ov, back.data());
                }));
            if (accepted)
            {
                std::fprintf(stderr, "ERROR: %s accepted a forged packet\n", name.c_str());
                failures++;
            }
        }
    }
    return failures ? 1 : 0;
}
