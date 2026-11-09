// VectorState.h - clear dirty upper YMM/ZMM state after foreign AVX code (x86 only).
//
// Found in experiment 002: after OpenSSL's AVX2/AVX-512 code runs, libsodium 1.0.18's
// legacy-SSE AES-NI code ran ~1.7x slower on an Intel Tiger Lake CPU (1260 vs 741 ns per
// 1400 B seal), because the CPU penalises SSE instructions while upper vector state is dirty.
// Executing VZEROUPPER after such code removes the penalty. It costs about one cycle.
#ifndef CRYPTO_BACKENDS_VECTORSTATE_H
#define CRYPTO_BACKENDS_VECTORSTATE_H

namespace crypto
{

#if defined(__x86_64__)
inline bool cpuHasAvx()
{
    static const bool has = __builtin_cpu_supports("avx");
    return has;
}

// VZEROUPPER keeps the low 128 bits of every register. The clobbers make the compiler assume
// xmm0-15 changed, so this is also safe in code built with -mavx.
inline void clearUpperVectorState()
{
    if (cpuHasAvx())
        asm volatile("vzeroupper" ::: "memory", "xmm0", "xmm1", "xmm2", "xmm3", "xmm4", "xmm5",
                     "xmm6", "xmm7", "xmm8", "xmm9", "xmm10", "xmm11", "xmm12", "xmm13", "xmm14",
                     "xmm15");
}
#else
inline void clearUpperVectorState() {}
#endif

} // namespace crypto

#endif // CRYPTO_BACKENDS_VECTORSTATE_H
