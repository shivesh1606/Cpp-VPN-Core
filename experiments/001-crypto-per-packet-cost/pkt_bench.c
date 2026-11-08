// Per-packet crypto cost benchmark: current XOR vs libsodium AEAD (+ replay window, handshake ops,
// and a UDP send syscall for context). Build: gcc -O2 (same as CMakeLists.txt).
#define _GNU_SOURCE
#include <sodium.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <x86intrin.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>

static volatile uint8_t sink;
static inline uint64_t now_ns(void) {
    struct timespec t; clock_gettime(CLOCK_MONOTONIC, &t);
    return (uint64_t)t.tv_sec * 1000000000ull + t.tv_nsec;
}

// Exact copy of XorCipher::crypt (crypto/XorCipher.cpp)
__attribute__((noinline))
void xor_crypt(const char data[], int len, char result[], uint8_t *xorkey) {
    for (int i = 0; i < len; i++) result[i] = data[i] ^ *xorkey;
}

// RFC 6479-style replay window, 2048 bits
typedef struct { uint64_t top; uint64_t bm[32]; } replay_t;
__attribute__((noinline))
int replay_check_update(replay_t *w, uint64_t ctr) {
    if (ctr + 2048 <= w->top) return 0;                       // too old
    if (ctr > w->top) {
        uint64_t cur = w->top >> 6, nw = ctr >> 6, diff = nw - cur;
        if (diff > 32) diff = 32;
        for (uint64_t i = 1; i <= diff; i++) w->bm[(cur + i) & 31] = 0;
        w->top = ctr;
    }
    uint64_t idx = (ctr >> 6) & 31, bit = 1ull << (ctr & 63);
    if (w->bm[idx] & bit) return 0;                           // replay
    w->bm[idx] |= bit; return 1;
}

typedef struct { const char *name; double ns, cyc; } res_t;
#define RUN(label, N, BODY) do {                                      \
    for (long _w = 0; _w < (N) / 10; _w++) { BODY; }                  \
    uint64_t _t0 = now_ns(), _c0 = __rdtsc();                         \
    for (long _i = 0; _i < (N); _i++) { BODY; }                       \
    uint64_t _c1 = __rdtsc(), _t1 = now_ns();                         \
    printf("  %-40s %9.1f ns  %9.0f TSC cyc\n", label,                \
           (double)(_t1 - _t0) / (N), (double)(_c1 - _c0) / (N));     \
} while (0)

int main(void) {
    if (sodium_init() < 0) return 1;
    unsigned char key[32], nonce[12] = {0}, ad[14] = {0x20, 4};
    randombytes_buf(key, sizeof key);
    static unsigned char in[2048], out[2048 + 16], back[2048];
    randombytes_buf(in, sizeof in);
    uint8_t xk = 0x5a;
    const long N = 1000000;
    int sizes[] = {64, 512, 1400};
    int aes = crypto_aead_aes256gcm_is_available();

    for (int s = 0; s < 3; s++) {
        int len = sizes[s];
        unsigned long long clen = 0, mlen = 0;
        uint64_t ctr = 0;
        printf("\npayload %d B\n", len);
        RUN("xor (current XorCipher::crypt)", N,
            { xor_crypt((char *)in, len, (char *)out, &xk); sink = out[0]; });
        RUN("chacha20poly1305-ietf seal", N, {
            memcpy(nonce + 4, &ctr, 8); ctr++;
            crypto_aead_chacha20poly1305_ietf_encrypt(out, &clen, in, len, ad, 14, NULL, nonce, key);
            sink = out[0]; });
        memcpy(nonce + 4, &ctr, 8);
        crypto_aead_chacha20poly1305_ietf_encrypt(out, &clen, in, len, ad, 14, NULL, nonce, key);
        RUN("chacha20poly1305-ietf open (valid)", N, {
            if (crypto_aead_chacha20poly1305_ietf_decrypt(back, &mlen, NULL, out, clen, ad, 14, nonce, key) != 0) return 2;
            sink = back[0]; });
        out[clen - 1] ^= 1;
        RUN("chacha20poly1305-ietf open (forged->drop)", N, {
            sink = (uint8_t)crypto_aead_chacha20poly1305_ietf_decrypt(back, &mlen, NULL, out, clen, ad, 14, nonce, key); });
        if (aes) {
            ctr = 0;
            RUN("aes256gcm seal (AES-NI)", N, {
                memcpy(nonce + 4, &ctr, 8); ctr++;
                crypto_aead_aes256gcm_encrypt(out, &clen, in, len, ad, 14, NULL, nonce, key);
                sink = out[0]; });
            memcpy(nonce + 4, &ctr, 8);
            crypto_aead_aes256gcm_encrypt(out, &clen, in, len, ad, 14, NULL, nonce, key);
            RUN("aes256gcm open (valid)", N, {
                if (crypto_aead_aes256gcm_decrypt(back, &mlen, NULL, out, clen, ad, 14, nonce, key) != 0) return 3;
                sink = back[0]; });
        }
    }

    printf("\nper-packet bookkeeping\n");
    replay_t w; memset(&w, 0, sizeof w); uint64_t c = 1;
    RUN("replay window check+update (in order)", 10000000L, { sink = (uint8_t)replay_check_update(&w, c++); });

    printf("\nper-handshake (once per connect / 120 s rekey)\n");
    unsigned char sk[32], pk[32], shared[32], h[64];
    randombytes_buf(sk, 32); crypto_scalarmult_base(pk, sk);
    RUN("X25519 scalarmult (Noise IK does 4/side)", 20000, { if (crypto_scalarmult(shared, sk, pk) != 0) return 5; sink = shared[0]; });
    unsigned char spk[32], ssk[64], sig[64], msg[88];
    crypto_sign_keypair(spk, ssk); randombytes_buf(msg, sizeof msg);
    crypto_sign_detached(sig, NULL, msg, sizeof msg, ssk);
    RUN("Ed25519 verify (ticket, server only)", 20000, {
        if (crypto_sign_verify_detached(sig, msg, sizeof msg, spk) != 0) return 4; });
    RUN("BLAKE2b-512 of 64 B (Noise MixHash)", 1000000, { crypto_generichash(h, 64, msg, 64, NULL, 0); sink = h[0]; });

    printf("\ncontext: kernel cost of sending one UDP datagram (sendto 1400 B, loopback)\n");
    int rx = socket(AF_INET, SOCK_DGRAM, 0), tx = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {0}; a.sin_family = AF_INET; a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    bind(rx, (struct sockaddr *)&a, sizeof a); socklen_t al = sizeof a; getsockname(rx, (struct sockaddr *)&a, &al);
    fcntl(tx, F_SETFL, O_NONBLOCK);
    RUN("sendto() 1400 B", 200000, { sendto(tx, in, 1400, 0, (struct sockaddr *)&a, sizeof a); });
    close(rx); close(tx);
    return 0;
}
