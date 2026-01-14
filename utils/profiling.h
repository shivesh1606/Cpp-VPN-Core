#include <cstdint>
#ifndef UTILS_PROFILING_H
#define UTILS_PROFILING_H

#ifndef ENABLE_PROFILING
#define ENABLE_PROFILING 0
#endif

#if ENABLE_PROFILING
#warning"PROFILING ENABLED"
#else
#warning "PROFILING DISABLED"
#endif

#if ENABLE_PROFILING

static inline uint64_t rdtsc_ordered()
{
    unsigned hi, lo;
    asm volatile(
        "lfence\n\t"
        "rdtsc\n\t"
        : "=a"(lo), "=d"(hi)
        :
        : "memory");
    return ((uint64_t)hi << 32) | lo;
}

#define RDTSC() rdtsc_ordered()

#else

#define RDTSC() 0

#endif

#define STAT_ADD(x, v) ((x) += (v))


#if ENABLE_PROFILING

#define PROFILE_SCOPE_START(var) uint64_t var = RDTSC()
#define PROFILE_SCOPE_END(var, stat) STAT_ADD(stat, (RDTSC() - (var)))

#else

#define PROFILE_SCOPE_START(var) do {} while (0)
#define PROFILE_SCOPE_END(var, stat) do {} while (0)

#endif

#endif // UTILS_PROFILING_H