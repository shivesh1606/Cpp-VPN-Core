/* This program calculates the Key for two persons
using the Diffie-Hellman Key exchange algorithm using C++ */
#include <cmath>
#include <iostream>

using namespace std;
long long int P=127;
long long int G=9;

long long int randomNumGen(int lower, int upper) {
    return rand() % (upper - lower + 1) + lower;
}
uint8_t calculateXORKey(uint32_t s) {
    return (s ^ (s >> 8) ^ (s >> 16) ^ (s >> 24)) & 0xFF;
}

// Power function to return value of a ^ b mod P
long long modexp(long long base, long long exp, long long mod)
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
