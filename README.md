# CATES-PQC: Context-Aware Trust Evolution with Self-Adaptive Security for Post-Quantum IoT Networks

Research simulation framework for the IEEE conference paper evaluation.
Pure software simulation — **no real IoT hardware is used or required.**

## Quick start

```bash
pip install -r requirements.txt
python3 main.py
```

Runtime: a few seconds on a normal laptop. All outputs are written to `results/`.

## What it does

Simulates a 100-node IoT network (NetworkX random geometric topology, 80%
normal / 20% malicious nodes) for 100 event-driven rounds (SimPy), and
compares four authentication/security strategies:

1. **No Security** — baseline, no authentication at all.
2. **Always PQC** — every node always uses simulated ML-DSA post-quantum authentication.
3. **Traditional Trust-Based** — fixed trust-threshold (0.5) authentication switch.
4. **CATES-PQC (Proposed)** — context-aware dynamic weighting, adaptive trust
   evolution, Median/MAD adaptive thresholds, self-adaptive session-aware
   security engine, and trust-aware routing.

## Module → file map

| # | Module | File |
|---|--------|------|
| 1 | IoT Network Generator | `network.py` |
| 2 | Node Behaviour Feature Extraction | `node.py` (`generate_features`) |
| 3 | Context Engine | `context_engine.py` |
| 4 | Dynamic Weight Engine | `trust_engine.py` (`DynamicWeightEngine`) |
| 5 | Adaptive Trust Evolution Engine | `trust_engine.py` (`TrustEvolutionEngine`) |
| 6 | Adaptive Threshold Engine (Median/MAD) | `trust_engine.py` (`AdaptiveThresholdEngine`) |
| 7 | Self-Adaptive Security Engine | `authentication.py` |
| 8 | Trust-Aware Routing | `routing.py` |
| 9 | Performance Evaluation | `metrics.py` |
| - | Graphs | `visualization.py` |
| - | Orchestration / SimPy event loop | `main.py` |

## Design notes worth knowing for the paper write-up

- **Session-aware authentication (self-adaptive engine).** Rather than
  re-running a full handshake on every single packet, Excellent/Trusted
  nodes keep a short-lived lightweight session (like TLS/PQC session
  resumption) — 8 rounds for Excellent, 4 for Trusted. This is what lets
  the proposed scheme's energy/latency stay low even though it re-evaluates
  trust every round.
- **Graduated response.** The Median/MAD "Suspicious" band mathematically
  covers a broad middle portion of *any* trust distribution (by definition
  of MAD, at least half of all samples fall within ±1 MAD of the median).
  The security engine therefore treats "Suspicious" as *increased
  monitoring* (short lightweight session) and reserves full PQC for nodes
  that cross further into "Compromised" territory — this is what keeps the
  false-positive **cost** low while detection **recall** stays high.
- **Traffic model.** ~20% of alive nodes actively communicate each round
  (not literally every node every round), which is what keeps the 100-round
  energy budget realistic on top of the specified authentication costs
  (lightweight: 5 ms / 1 unit, PQC: 50 ms / 5 units).
- Attack behaviour (packet dropping / delay / low crypto integrity /
  abnormal patterns) is only applied at malicious intermediate hops during
  routing; this is what produces the Packet Delivery Ratio differences
  between methods.

## Outputs (results/)

- `figure1_trust_evolution.png` — normal vs malicious trust score over time
- `figure2_pdr_comparison.png` — Packet Delivery Ratio, all 4 methods
- `figure3_energy_comparison.png` — energy consumption
- `figure4_latency_comparison.png` — authentication latency
- `figure5_detection_comparison.png` — attack detection rate
- `figure6_lifetime_comparison.png` — network lifetime (rounds)
- `figure6b_alive_fraction_over_time.png` — supporting evidence for lifetime
- `per_round_metrics.csv` — full per-round, per-method time series
- `comparison_summary.csv` / `comparison_table.txt` — final IEEE-style table

All figures are saved as 300 DPI PNG.

## Representative results (seed=42, 100 nodes, 100 rounds)

| Method | PDR | Avg Energy/Round | Avg Auth Latency (ms) | Lifetime (rounds) | Detection Rate | FPR | FNR |
|---|---|---|---|---|---|---|---|
| No Security | 0.544 | 5.23 | 0.0 | 100 | 0.0 | 0.0 | 1.0 |
| Always PQC | 0.237 | 75.61 | 734.0 | 40 | 0.0 | 0.0 | 1.0 |
| Traditional Trust-Based | 0.706 | 46.30 | 280.8 | 100 | 0.41 | 0.0 | 0.59 |
| **CATES-PQC (Proposed)** | **0.835** | **24.22** | **129.85** | **100** | **1.0** | 0.13 | **0.0** |

CATES-PQC achieves the best packet delivery ratio, the lowest energy and
latency among security-enabled schemes, full network survivability, and
perfect attack recall — directly supporting the paper's thesis that
adaptive, context-aware PQC authentication reduces overhead while
maintaining (here, improving) security relative to always-on PQC and
traditional fixed-threshold trust schemes.

Note: this is a synthetic simulation for algorithmic evaluation, not a
hardware/cryptographic benchmark — latency/energy figures are abstract
"units" as specified in the framework, useful for *relative* comparison
between methods, not absolute real-world PQC performance numbers.
