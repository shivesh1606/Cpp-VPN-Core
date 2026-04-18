#ifndef DIFFIEHELLMAN_H
#define DIFFIEHELLMAN_H

#include <cstdint>
#include <cstdlib>

inline constexpr long long P = 127;
inline constexpr long long G = 9;

inline long long randomNumGen(int lower, int upper)
{
    return std::rand() % (upper - lower + 1) + lower;
}

inline uint8_t calculateXORKey(uint32_t s)
{
    return static_cast<uint8_t>((s ^ (s >> 8) ^ (s >> 16) ^ (s >> 24)) & 0xFF);
}

// Power function to return value of a ^ b mod mod
inline long long modexp(long long base, long long exp, long long mod)
{
    long long result = 1;
    base = base % mod;

    while (exp > 0)
    {
        if (exp & 1)
            result = (result * base) % mod;

        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

#endif // DIFFIEHELLMAN_H
