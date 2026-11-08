// ReplayWindow.h - sliding anti-replay window for transport counters (design 01 C6).
//
// RFC 6479 ("IPsec Anti-Replay Algorithm without Bit Shifting"): a ring of 32 x 64-bit blocks.
// The block holding the highest counter is partly in the future, so the usable window is
// (32 - 1) * 64 = 1984 counters behind the highest one seen. Measured cost: ~2 ns (experiment 001).
//
// Usage on receive: check() before decrypting (cheap reject), update() only after the packet
// authenticated, so forged packets cannot move the window.
#ifndef PROTOCOL_V2_REPLAYWINDOW_H
#define PROTOCOL_V2_REPLAYWINDOW_H

#include <cstdint>
#include <cstring>

namespace v2
{

class ReplayWindow
{
public:
    static constexpr unsigned kBlocks = 32;
    static constexpr uint64_t kWindow = (kBlocks - 1) * 64; // 1984

    // True if `ctr` is new and inside the window.
    bool check(uint64_t ctr) const
    {
        if (!seen_any_ || ctr > top_)
            return true;
        if (top_ - ctr >= kWindow)
            return false; // too old
        return !(bm_[(ctr >> 6) & (kBlocks - 1)] & (uint64_t(1) << (ctr & 63)));
    }

    // Marks `ctr` as received. Call only after check() and successful authentication.
    void update(uint64_t ctr)
    {
        if (!seen_any_)
        {
            std::memset(bm_, 0, sizeof(bm_));
            top_ = ctr;
            seen_any_ = true;
        }
        else if (ctr > top_)
        {
            const uint64_t cur = top_ >> 6, idx = ctr >> 6;
            uint64_t diff = idx - cur;
            if (diff > kBlocks)
                diff = kBlocks;
            for (uint64_t i = 1; i <= diff; i++)
                bm_[(cur + i) & (kBlocks - 1)] = 0;
            top_ = ctr;
        }
        bm_[(ctr >> 6) & (kBlocks - 1)] |= uint64_t(1) << (ctr & 63);
    }

    uint64_t highest() const { return top_; }

private:
    uint64_t bm_[kBlocks] = {0};
    uint64_t top_ = 0;
    bool seen_any_ = false;
};

} // namespace v2

#endif // PROTOCOL_V2_REPLAYWINDOW_H
