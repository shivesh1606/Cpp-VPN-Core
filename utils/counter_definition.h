#ifndef UTILS_COUNTER_DEFINITION_H
#define UTILS_COUNTER_DEFINITION_H

#include <cstdint>
#include <iostream>
#include <ctime>
#include <cfloat>

#include "utils/logger.h"
#include "utils/profiling.h" // <-- IMPORTANT

struct Stats
{
    // ============================================================
    // Packet counters (ALWAYS ENABLED)
    // ============================================================

    uint64_t udp_rx_pkts = 0;
    uint64_t udp_rx_bytes = 0;

    uint64_t tun_tx_pkts = 0;
    uint64_t tun_tx_bytes = 0;

    uint64_t tun_rx_pkts = 0;
    uint64_t tun_rx_bytes = 0;

    uint64_t udp_tx_pkts = 0;
    uint64_t udp_tx_bytes = 0;

    // ============================================================
    // Control / error counters (ALWAYS ENABLED)
    // ============================================================

    uint64_t handshake_pkts = 0;
    uint64_t handshake_failures = 0;

    uint64_t tun_rx_drops = 0;
    uint64_t udp_tx_drops = 0;
    uint64_t udp_rx_drops = 0;

    uint64_t tun_read_eagain = 0;
    uint64_t udp_recv_eagain = 0;

    // ============================================================
    // Batching (ALWAYS ENABLED)
    // ============================================================

    uint64_t udp_rx_batches = 0;
    uint64_t udp_tx_batches = 0;

    double avg_pkts_per_rx_batch = 0.0;
    double avg_pkts_per_tx_batch = 0.0;

    double max_avg_pkts_per_rx_batch = 0.0;
    double max_avg_pkts_per_tx_batch = 0.0;

#if ENABLE_PROFILING
    // ============================================================
    // Cycle accumulators (PROFILING ONLY)
    // ============================================================

    uint64_t enc_cycles = 0;
    uint64_t dec_cycles = 0;
    uint64_t lookup_cycles = 0;
    uint64_t rx_userspace_cycles = 0;

    uint64_t rx_syscall_cycles = 0;
    uint64_t tx_syscall_cycles = 0;
    uint64_t tun_write_cycles = 0;
    uint64_t tun_read_cycles = 0;
    // ============================================================
    // Derived metrics (PROFILING ONLY)
    // ============================================================

    double enc_cyc_per_pkt = 0.0;
    double dec_cyc_per_pkt = 0.0;
    double lookup_cyc_per_pkt = 0.0;
    double rx_userspace_cyc_per_pkt = 0.0;

    double rx_syscall_cyc_per_pkt = 0.0;
    double tx_syscall_cyc_per_pkt = 0.0;
    double tun_write_cyc_per_pkt = 0.0;
    double tun_read_cyc_per_pkt = 0.0;
#endif

    // ============================================================
    // Timekeeping
    // ============================================================

    time_t last_reset_time = time(nullptr);

    // ============================================================
    // Min / Max tracking (ALWAYS ENABLED)
    // ============================================================

    double max_udp_mbps = 0.0;
    double min_udp_mbps = DBL_MAX; // Use DBL_MAX from <cfloat>
    double max_tun_mbps = 0.0;
    double min_tun_mbps = DBL_MAX;

    // ============================================================
    // Reset
    // ============================================================

    void reset_Stats()
    {
        udp_rx_pkts = udp_rx_bytes = 0;
        tun_tx_pkts = tun_tx_bytes = 0;
        tun_rx_pkts = tun_rx_bytes = 0;
        udp_tx_pkts = udp_tx_bytes = 0;

        handshake_pkts = handshake_failures = 0;
        tun_rx_drops = udp_tx_drops = udp_rx_drops = 0;

        tun_read_eagain = udp_recv_eagain = 0;

        udp_rx_batches = udp_tx_batches = 0;

        avg_pkts_per_rx_batch = 0.0;
        avg_pkts_per_tx_batch = 0.0;

#if ENABLE_PROFILING
        enc_cycles = dec_cycles = 0;
        lookup_cycles = 0;
        rx_userspace_cycles = 0;
        rx_syscall_cycles = 0;
        tx_syscall_cycles = 0;
        tun_write_cycles = 0;
        tun_read_cycles = 0;

#endif

        last_reset_time = time(nullptr);
    }

    // ============================================================
    // Print
    // ============================================================

    void print_Stats()
    {
        time_t now = time(nullptr);
        if (last_reset_time == 0)
        {
            last_reset_time = now;
            return;
        }

        time_t delta = now - last_reset_time;
        if (delta == 0)
            delta = 1;

        // ---- Mbps ----
        // Use double for the calculation
        double udp_mbps = (static_cast<double>(udp_rx_bytes) * 8.0) / (static_cast<double>(delta) * 1000000.0);

        max_udp_mbps = std::max(max_udp_mbps, udp_mbps);
        if (udp_rx_pkts > 0)
        { // Only track min when there is actually traffic
            min_udp_mbps = std::min(min_udp_mbps, udp_mbps);
        }

        double tun_mbps = (static_cast<double>(tun_tx_bytes) * 8.0) / (static_cast<double>(delta) * 1000000.0);
        max_tun_mbps = std::max(max_tun_mbps, tun_mbps);
        if (tun_tx_pkts > 0)
        { // Only track min when there is actually traffic
            min_tun_mbps = std::min(min_tun_mbps, tun_mbps);
        }

        // ---- Batching efficiency ----
        if (udp_rx_batches > 0)
        {
            avg_pkts_per_rx_batch =
                static_cast<double>(udp_rx_pkts) / udp_rx_batches;
            max_avg_pkts_per_rx_batch =
                std::max(max_avg_pkts_per_rx_batch, avg_pkts_per_rx_batch);
        }

        if (udp_tx_batches > 0)
        {
            avg_pkts_per_tx_batch =
                static_cast<double>(udp_tx_pkts) / udp_tx_batches;
            max_avg_pkts_per_tx_batch =
                std::max(max_avg_pkts_per_tx_batch, avg_pkts_per_tx_batch);
        }

#if ENABLE_PROFILING
        enc_cyc_per_pkt =
            udp_tx_pkts ? (double)enc_cycles / udp_tx_pkts : 0;

        dec_cyc_per_pkt =
            udp_rx_pkts ? (double)dec_cycles / udp_rx_pkts : 0;

        lookup_cyc_per_pkt =
            udp_rx_pkts ? (double)lookup_cycles / udp_rx_pkts : 0;

        rx_userspace_cyc_per_pkt =
            udp_rx_pkts ? (double)rx_userspace_cycles / udp_rx_pkts : 0;

        rx_syscall_cyc_per_pkt =
            udp_rx_pkts ? (double)rx_syscall_cycles / udp_rx_pkts : 0;

        tx_syscall_cyc_per_pkt =
            udp_tx_pkts ? (double)tx_syscall_cycles / udp_tx_pkts : 0;

        tun_write_cyc_per_pkt =
            tun_tx_pkts ? (double)tun_write_cycles / tun_tx_pkts : 0;

        tun_read_cyc_per_pkt =
            tun_rx_pkts ? (double)tun_read_cycles / tun_rx_pkts : 0;
#endif

        // ---- Always print functional stats ----
        LOG(LOG_INFO,
            "---- Stats (last %ld sec) ----\n"
            "UDP RX: %lu pkts, %lu bytes, %.2f Mbps (max: %.2f, min: %.2f)\n"
            "TUN TX: %lu pkts, %lu bytes, %.2f Mbps (max: %.2f, min: %.2f)\n"
            "Handshake pkts: %lu, failures: %lu\n"
            "Drops - TUN RX: %lu, UDP TX: %lu, UDP RX: %lu\n"
            "EAGAIN - TUN read: %lu, UDP recv: %lu\n"
            "UDP RX batches: %lu, avg pkts/batch: %.2f (max avg: %.2f)\n"
            "UDP TX batches: %lu, avg pkts/batch: %.2f (max avg: %.2f)\n",
            delta,
            udp_rx_pkts, udp_rx_bytes, udp_mbps, max_udp_mbps,
            (min_udp_mbps == UINT64_MAX ? 0 : min_udp_mbps),
            tun_tx_pkts, tun_tx_bytes, tun_mbps, max_tun_mbps,
            (min_tun_mbps == UINT64_MAX ? 0 : min_tun_mbps),
            handshake_pkts, handshake_failures,
            tun_rx_drops, udp_tx_drops, udp_rx_drops,
            tun_read_eagain, udp_recv_eagain,
            udp_rx_batches, avg_pkts_per_rx_batch, max_avg_pkts_per_rx_batch,
            udp_tx_batches, avg_pkts_per_tx_batch, max_avg_pkts_per_tx_batch);

#if ENABLE_PROFILING
        // ---- Profiling-only stats ----
        LOG(LOG_INFO,
            "Enc cycles/pkt: %.2f, Dec cycles/pkt: %.2f\n"
            "Lookup cycles/pkt: %.2f, RX userspace cycles/pkt: %.2f\n"
            "RX syscall cycles/pkt: %.2f, TX syscall cycles/pkt: %.2f, TUN write cycles/pkt: %.2f, TUN read cycles/pkt: %.2f\n",
            enc_cyc_per_pkt,
            dec_cyc_per_pkt,
            lookup_cyc_per_pkt,
            rx_userspace_cyc_per_pkt,
            rx_syscall_cyc_per_pkt,
            tx_syscall_cyc_per_pkt,
            tun_write_cyc_per_pkt,
            tun_read_cyc_per_pkt);
#endif

        log_flush();
    }
};

extern Stats global_stats;

#endif
