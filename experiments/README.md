# Experiments

Measurements that inform design decisions. Design docs ([docs/design/](../docs/design/README.md)) cite these results; the raw data lives here.

## Conventions

- One folder per experiment: `NNN-short-name/`, numbered in creation order and never renumbered.
- Each folder contains:
  - `README.md`: question, hypothesis, environment, method, results, conclusion, and how to reproduce
  - the source code and run script, self-contained and with no dependency on engine internals unless stated
  - `results/<YYYY-MM-DD>_<cpu-or-host>_<env>.txt`: raw, unedited output, one file per run session
- Re-running on new hardware adds a new results file and a row to the experiment's results table. Old data is never overwritten.
- Report environment details: CPU, OS/VM, compiler and flags, library versions, pinning, iteration count.

## Index

| # | Experiment | Question | Status | Used by |
|---|---|---|---|---|
| 001 | [Per-packet crypto cost](001-crypto-per-packet-cost/README.md) | How much time does replacing XOR with AEAD add per data packet? | Done on a dev laptop; target-node runs pending | [Design 01 §5.1](../docs/design/01-cipher-layer.md) |

## Planned

| # | Experiment | Depends on |
|---|---|---|
| 002 | `crypto_bench` on target nodes (GCP e2-micro x86, Oracle A1 arm64), all backends | Plan milestone M2 |
| 003 | End-to-end tunnel throughput and latency: XOR (v1) vs AEAD (v2) over the same path (Windows client → node) | M4 |
| 004 | Handshake rate and CPU cost under a HELLO flood (mac1 effectiveness) | M4 |
