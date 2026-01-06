#ifndef UTILS_COUNTER_DEFINITION_H
#define UTILS_COUNTER_DEFINITION_H

#include <cstdint>
#include <iostream>
#include <ctime>
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

    // ---------- Crypto (future) ----------
    uint64_t enc_cycles = 0;
    uint64_t dec_cycles = 0;

    // ---------- Bandwidth ----------
    uint64_t max_udp_mbps = 0;
    uint64_t min_udp_mbps = UINT64_MAX;
    uint64_t max_tun_mbps = 0;
    uint64_t min_tun_mbps = UINT64_MAX;

    time_t last_reset_time = time(nullptr);

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

        std::cout
            << "\n===== VPN STATS =====\n"
            << "UDP RX: pkts=" << udp_rx_pkts
            << " bytes=" << udp_rx_bytes
            << " batches=" << udp_rx_batches << "\n"

            << "UDP TX: pkts=" << udp_tx_pkts
            << " bytes=" << udp_tx_bytes
            << " batches=" << udp_tx_batches << "\n"

            << "TUN RX: pkts=" << tun_rx_pkts
            << " bytes=" << tun_rx_bytes << "\n"

            << "TUN TX: pkts=" << tun_tx_pkts
            << " bytes=" << tun_tx_bytes << "\n"

            << "Drops: tun_rx=" << tun_rx_drops
            << " udp_rx=" << udp_rx_drops
            << " udp_tx=" << udp_tx_drops << "\n"

            << "EAGAIN: tun=" << tun_read_eagain
            << " udp=" << udp_recv_eagain << "\n"

            << "Avg RX pkts/batch=" << avg_pkts_per_rx_batch
            << " (max=" << max_avg_pkts_per_rx_batch << ")\n"

            << "Avg TX pkts/batch=" << avg_pkts_per_tx_batch
            << " (max=" << max_avg_pkts_per_tx_batch << ")\n"

            << "UDP Mbps=" << udp_mbps
            << " (max=" << max_udp_mbps
            << " min=" << min_udp_mbps << ")\n"

            << "TUN Mbps=" << tun_mbps
            << " (max=" << max_tun_mbps
            << " min=" << min_tun_mbps << ")\n"
            << "=====================\n";
    }
};

extern Stats global_stats;

#endif
