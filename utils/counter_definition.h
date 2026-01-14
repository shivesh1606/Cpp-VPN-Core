#ifndef UTILS_COUNTER_DEFINITION_H
#define UTILS_COUNTER_DEFINITION_H

#include <cstdint>
#include <iostream>
#include <ctime>
#include "utils/logger.h"
#include <cfloat>

struct Stats
{
    // ---------- Packet counters ----------
    uint64_t udp_rx_pkts = 0;
    uint64_t udp_rx_bytes = 0;

    uint64_t tun_tx_pkts = 0;
    uint64_t tun_tx_bytes = 0;

    uint64_t tun_rx_pkts = 0;
    uint64_t tun_rx_bytes = 0;

    uint64_t udp_tx_pkts = 0;
    uint64_t udp_tx_bytes = 0;

    // ---------- Control / errors ----------
    uint64_t handshake_pkts = 0;
    uint64_t handshake_failures = 0;

    uint64_t tun_rx_drops = 0;
    uint64_t udp_tx_drops = 0;
    uint64_t udp_rx_drops = 0;

    uint64_t tun_read_eagain = 0;
    uint64_t udp_recv_eagain = 0;

    // ---------- Batching ----------
    uint64_t udp_rx_batches = 0;
    uint64_t udp_tx_batches = 0;

    double avg_pkts_per_rx_batch = 0.0;
    double avg_pkts_per_tx_batch = 0.0;

    double max_avg_pkts_per_rx_batch = 0.0;
    double max_avg_pkts_per_tx_batch = 0.0;
    double enc_cyc_per_pkt = 0.0;
    double dec_cyc_per_pkt = 0.0;

    double lookup_cyc_per_pkt = 0.0;
    double rx_batch_cyc_per_pkt = 0.0;
    // ---------- Crypto (future) ----------
    uint64_t enc_cycles = 0;
    uint64_t dec_cycles = 0;

    // ---------- Bandwidth ----------
    uint64_t max_udp_mbps = 0;
    uint64_t min_udp_mbps = UINT64_MAX;
    uint64_t max_tun_mbps = 0;
    uint64_t min_tun_mbps = UINT64_MAX;

    time_t last_reset_time = time(nullptr);

    // ---------- Syscalls ----------
    uint64_t lookup_cycles = 0;
    uint64_t rx_batch_cycles = 0;
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

        enc_cycles = dec_cycles = 0;
        lookup_cycles = 0;
        rx_batch_cycles = 0;

        last_reset_time = time(nullptr);
    }

    void print_Stats()
    {
        time_t now = time(nullptr);
        time_t delta = now - last_reset_time;
        if (delta == 0)
            delta = 1;

        // ---- Mbps ----
        uint64_t udp_mbps = (udp_rx_bytes * 8) / (delta * 1000000);
        max_udp_mbps = std::max(max_udp_mbps, udp_mbps);
        min_udp_mbps = std::min(min_udp_mbps, udp_mbps);

        uint64_t tun_mbps = (tun_tx_bytes * 8) / (delta * 1000000);
        max_tun_mbps = std::max(max_tun_mbps, tun_mbps);
        min_tun_mbps = std::min(min_tun_mbps, tun_mbps);

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
        enc_cyc_per_pkt =
            udp_tx_pkts ? (double)enc_cycles / udp_tx_pkts : 0;

        dec_cyc_per_pkt =
            udp_rx_pkts ? (double)dec_cycles / udp_rx_pkts : 0;

        lookup_cyc_per_pkt =
            udp_rx_pkts ? (double)lookup_cycles / udp_rx_pkts : 0;
        rx_batch_cyc_per_pkt =
            udp_rx_pkts ? (double)rx_batch_cycles / udp_rx_pkts : 0;
        LOG(LOG_INFO,
            "---- Stats (last %ld sec) ----\n"
            "UDP RX: %lu pkts, %lu bytes, %lu Mbps (max: %lu, min: %lu)\n"
            "TUN TX: %lu pkts, %lu bytes, %lu Mbps (max: %lu, min: %lu)\n"
            "Handshake pkts: %lu, failures: %lu\n"
            "Drops - TUN RX: %lu, UDP TX: %lu, UDP RX: %lu\n"
            "EAGAIN - TUN read: %lu, UDP recv: %lu\n"
            "UDP RX batches: %lu, avg pkts/batch: %.2f (max avg: %.2f)\n"
            "UDP TX batches: %lu, avg pkts/batch: %.2f (max avg: %.2f)\n"
            "Enc cycles/pkt: %.2f, Dec cycles/pkt: %.2f\n",
            "Lookup cycles/pkt: %.2f, RX batch cycles/pkt: %.2f\n",
            delta,
            udp_rx_pkts, udp_rx_bytes, udp_mbps, max_udp_mbps,
            (min_udp_mbps == UINT64_MAX ? 0 : min_udp_mbps),
            tun_tx_pkts, tun_tx_bytes, tun_mbps, max_tun_mbps,
            (min_tun_mbps == UINT64_MAX ? 0 : min_tun_mbps),
            handshake_pkts, handshake_failures,
            tun_rx_drops, udp_tx_drops, udp_rx_drops,
            tun_read_eagain, udp_recv_eagain,
            udp_rx_batches, avg_pkts_per_rx_batch, max_avg_pkts_per_rx_batch,
            udp_tx_batches, avg_pkts_per_tx_batch, max_avg_pkts_per_tx_batch,
            enc_cyc_per_pkt, dec_cyc_per_pkt, lookup_cyc_per_pkt, rx_batch_cyc_per_pkt);

        log_flush();
    }
};

extern Stats global_stats;

#endif
