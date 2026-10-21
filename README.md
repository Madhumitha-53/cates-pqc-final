# CATES-PQC research simulation

## Requirements and reproduction

- Python 3.10 or newer
- Dependencies in `requirements.txt`: NetworkX, SimPy, NumPy, Matplotlib,
  pandas, and SciPy

```powershell
python -m pip install -r requirements.txt
python experiments.py
```

The complete run uses seeds 42–61 (20 seeds), 100 rounds, malicious ratios
0%, 10%, 20%, 30%, and 40%, and both `constant` and `on_off` attacks. It also
runs 400-round lifetime trials at 20% malicious for both attack modes. The
lifetime is the first round when the physically alive-node fraction falls below
0.5; if not reached, the raw value is blank. The default uses two local worker
processes; `--workers 1` runs serially.

For a small CLI smoke run:

```powershell
python experiments.py --seeds 1 --seed-start 42 --ratios 0 0.2 --attack-modes constant on_off --workers 2 --output-dir results\smoke
```

`results/config.json` records the simulation and method configuration. Main
outputs include raw per-seed records, mean/sample-standard-deviation summaries,
paired tests, separate parameter-sweep CSVs, time-series CSVs, and publication
figures at 300 DPI. In `experiment_raw.csv`, each row is a method/scenario/seed
summary; round-level records are not emitted.
`paired_stats.csv` contains the paired bootstrap/Wilcoxon results;
`pqc_cost_sweep_raw.csv` and `lambda_threshold_sweep_raw.csv` contain the
sensitivity trials and their corresponding `*_mean_std.csv` files are their
aggregates. Figure 1 separates constant and on-off attacks and zooms the
on-off trust axis to make its variation visible.

Run the 20-seed MAD-floor/absolute-guard and distribution-shift study separately
with:

```powershell
python experiments.py --guard-shift-only --seeds 20 --seed-start 42 --workers 2
```

This writes `mad_floor_sweep_raw.csv`, `mad_floor_sweep_mean_std.csv`,
`distribution_shift_raw.csv`, `distribution_shift_mean_std.csv`, appends the
paired comparisons to `paired_stats.csv`, and creates the 300-DPI
`figure11_shift_fpr_before_after.png`. Sweep settings use seeds 42–61; the
shift begins at round 50 (rounds 1–49 are before, rounds 50–100 are after).
The absolute guard downgrades an adaptive Compromised/Quarantined label to
Suspicious whenever trust is at least `abs_floor`; `None` disables that guard.

## Latest results

All values below are mean ± sample standard deviation across 20 seeds from the
latest full run. For 400-round lifetime, `not reached` means no run crossed the
half-alive threshold. `TTD` is the mean first flagged round among malicious
nodes that were detected; coverage is available in the CSV. Honest-state shares
are averaged over rounds and over honest nodes alive in each round.

### 20% malicious, constant attack

| Method | PDR | Energy/round | Auth latency/round (ms) | Lifetime (400-round run) | Detection | FPR |
|---|---:|---:|---:|---:|---:|---:|
| No Security | 59.7% ± 8.7% | 5.20 ± 0.02 | 0.00 ± 0.00 | Not reached (20/20) | 0.0% ± 0.0% | 0.0% ± 0.0% |
| Always PQC | 27.9% ± 4.8% | 76.78 ± 1.63 | 745.42 ± 15.82 | 42.9 ± 1.6 | 0.0% ± 0.0% | 0.0% ± 0.0% |
| Traditional Trust-Based | 75.2% ± 8.0% | 46.82 ± 0.60 | 285.19 ± 5.46 | 173.7 ± 7.5 | 43.2% ± 2.6% | 0.0% ± 0.0% |
| CATES-PQC | 88.1% ± 7.8% | 24.11 ± 1.22 | 124.39 ± 15.04 | 280.4 ± 11.7 | 100.0% ± 0.0% | 8.8% ± 3.8% |
| CATES no routing/quarantine | 70.4% ± 11.2% | 47.29 ± 1.70 | 368.10 ± 19.58 | 109.5 ± 10.9 | 42.7% ± 2.5% | 11.7% ± 1.5% |
| CATES no cache | 87.6% ± 7.9% | 33.12 ± 0.60 | 173.67 ± 11.71 | 209.9 ± 6.1 | 100.0% ± 0.0% | 10.2% ± 3.9% |
| CATES fixed weights | 87.8% ± 7.8% | 24.44 ± 1.09 | 129.26 ± 13.29 | 284.4 ± 11.3 | 100.0% ± 0.0% | 9.5% ± 3.1% |
| CATES fixed thresholds | 88.9% ± 8.0% | 14.63 ± 0.32 | 55.80 ± 2.27 | 375.1 ± 14.0 (4/20 not reached) | 100.0% ± 0.0% | 0.0% ± 0.0% |
| Fixed Trust + Cache | 75.2% ± 8.0% | 35.33 ± 0.62 | 227.76 ± 5.50 | 250.4 ± 11.8 | 43.2% ± 2.6% | 0.0% ± 0.0% |
| Fixed Trust + Routing | 89.3% ± 6.4% | 46.87 ± 0.70 | 285.43 ± 5.81 | 175.2 ± 6.9 | 43.4% ± 2.9% | 0.0% ± 0.0% |

### 400-round lifetime at 20% malicious

| Method | Constant | On-off |
|---|---:|---:|
| No Security | Not reached (20/20) | Not reached (20/20) |
| Always PQC | 42.9 ± 1.6 | 42.9 ± 1.3 |
| Traditional Trust-Based | 173.7 ± 7.5 | 175.1 ± 6.5 |
| CATES-PQC | 280.4 ± 11.7 | 272.5 ± 12.7 |
| CATES no routing/quarantine | 109.5 ± 10.9 | 103.5 ± 5.9 |
| CATES no cache | 209.9 ± 6.1 | 208.8 ± 5.9 |
| CATES fixed weights | 284.4 ± 11.3 | 278.5 ± 11.3 |
| CATES fixed thresholds | 375.1 ± 14.0 (4/20 not reached) | 290.6 ± 17.4 |
| Fixed Trust + Cache | 250.4 ± 11.8 | 242.4 ± 11.4 |
| Fixed Trust + Routing | 175.2 ± 6.9 | 175.5 ± 7.7 |

At 20% constant attack, the per-run mean detection time is 1.0 ± 0.0 rounds
for both CATES and the fixed-trust methods that detect malicious nodes. CATES
has mean delivered-packet hop count 4.49 ± 0.48 and throughput 12.62 ± 1.26
packets/round.

### CATES across malicious ratios

| Attack | Malicious | PDR | Detection | FPR |
|---|---:|---:|---:|---:|
| Constant | 0% | 88.7% ± 5.5% | N/A | 27.3% ± 3.2% |
| Constant | 10% | 88.3% ± 6.4% | 100.0% ± 0.0% | 19.3% ± 3.4% |
| Constant | 20% | 88.1% ± 7.8% | 100.0% ± 0.0% | 8.8% ± 3.8% |
| Constant | 30% | 86.5% ± 10.4% | 100.0% ± 0.0% | 2.0% ± 1.7% |
| Constant | 40% | 77.6% ± 17.1% | 100.0% ± 0.0% | 0.2% ± 0.5% |
| On-off | 0% | 88.7% ± 5.5% | N/A | 27.3% ± 3.2% |
| On-off | 10% | 89.0% ± 6.1% | 91.6% ± 2.8% | 19.4% ± 3.2% |
| On-off | 20% | 88.9% ± 5.5% | 90.2% ± 1.5% | 10.1% ± 3.7% |
| On-off | 30% | 88.3% ± 6.2% | 88.4% ± 1.8% | 2.5% ± 1.9% |
| On-off | 40% | 85.6% ± 7.3% | 84.1% ± 2.0% | 0.1% ± 0.1% |

With no attackers, detection is N/A because there are no malicious nodes.
CATES honest-node state shares are Excellent 1.6% ± 1.5%,
Trusted 21.0% ± 2.4%, Suspicious 50.1% ± 0.0%, Compromised 10.9% ± 1.4%, and
Quarantined 16.5% ± 2.0%. The false-positive rate is 27.3% ± 3.2%; a state
label of Suspicious is not counted as a positive detection.

### Guarded MAD and absolute-floor sweep

These results are 20-seed means ± sample standard deviations for constant
attacks. At 20% malicious, detection remained 100% for every setting. A
`None` absolute floor disables the guard; lifetimes are means ± SD over the
400-round trials, with not-reached counts shown in the final column.

| MAD floor | Abs floor | PDR | Energy/round | Auth latency (ms) | Detection | FPR | Lifetime |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 0.01 | 0.6 | 89.24% ± 7.81% | 21.82 ± 0.41 | 88.90 ± 2.34 | 100% ± 0% | 0.14% ± 0.18% | 289.9 ± 13.5 |
| 0.03 | 0.6 | 89.36% ± 7.57% | 21.82 ± 0.43 | 88.40 ± 2.27 | 100% ± 0% | 0.06% ± 0.10% | 287.2 ± 15.0 |
| 0.05 | 0.6 | 89.13% ± 7.92% | 21.97 ± 0.38 | 89.09 ± 1.87 | 100% ± 0% | 0.05% ± 0.11% | 286.5 ± 12.0 |
| 0.10 | 0.6 | 89.21% ± 8.05% | 24.71 ± 0.28 | 104.40 ± 1.87 | 100% ± 0% | 0.05% ± 0.11% | 265.6 ± 9.6 |
| 0.01 | None | 88.09% ± 7.75% | 24.11 ± 1.22 | 124.39 ± 15.04 | 100% ± 0% | 8.83% ± 3.77% | 280.4 ± 11.7 |
| 0.03 | None | 88.24% ± 8.11% | 23.99 ± 1.15 | 122.84 ± 14.28 | 100% ± 0% | 8.76% ± 3.60% | 279.9 ± 11.4 |
| 0.05 | None | 88.25% ± 7.69% | 23.91 ± 1.08 | 120.11 ± 13.37 | 100% ± 0% | 7.80% ± 3.28% | 277.6 ± 9.3 |
| 0.10 | None | 89.48% ± 7.99% | 24.66 ± 0.31 | 105.82 ± 3.52 | 100% ± 0% | 0.43% ± 0.63% | 267.2 ± 10.6 |

At 0% malicious, detection is N/A for all settings. Performance/FPR and
honest-node state shares are:

| MAD floor | Abs floor | PDR | Energy/round | Auth latency (ms) | FPR | Honest shares E / T / S / C / Q |
|---:|---:|---:|---:|---:|---:|---|
| 0.01 | 0.6 | 93.43% ± 0.90% | 27.72 ± 0.51 | 114.40 ± 2.78 | 0.26% ± 0.04% | 8.2% ± 4.5% / 19.3% ± 3.9% / 72.3% ± 2.5% / 0.2% ± 0.0% / 0.1% ± 0.0% |
| 0.03 | 0.6 | 93.58% ± 0.89% | 27.34 ± 0.50 | 110.67 ± 2.53 | 0.00% ± 0.01% | 9.1% ± 5.0% / 18.6% ± 3.7% / 72.3% ± 2.8% / 0.0% ± 0.0% / 0.0% ± 0.0% |
| 0.05 | 0.6 | 93.67% ± 0.82% | 28.22 ± 0.48 | 115.06 ± 2.39 | 0.00% ± 0.01% | 4.9% ± 2.9% / 17.5% ± 2.1% / 77.6% ± 3.4% / 0.0% ± 0.0% / 0.0% ± 0.0% |
| 0.10 | 0.6 | 93.75% ± 0.75% | 30.82 ± 0.16 | 128.20 ± 0.80 | 0.01% ± 0.02% | 0.0% ± 0.0% / 1.4% ± 1.6% / 98.6% ± 1.6% / 0.0% ± 0.0% / 0.0% ± 0.0% |
| 0.01 | None | 88.76% ± 5.34% | 34.40 ± 1.40 | 222.92 ± 16.62 | 27.40% ± 3.16% | 1.4% ± 1.4% / 21.0% ± 2.4% / 50.1% ± 0.0% / 10.9% ± 1.3% / 16.6% ± 2.1% |
| 0.03 | None | 89.24% ± 5.48% | 33.97 ± 1.33 | 215.93 ± 15.47 | 26.06% ± 2.95% | 1.6% ± 1.8% / 21.2% ± 2.1% / 51.1% ± 0.1% / 10.5% ± 1.4% / 15.7% ± 1.8% |
| 0.05 | None | 90.51% ± 4.11% | 32.72 ± 1.42 | 195.34 ± 16.72 | 21.49% ± 2.89% | 2.6% ± 2.1% / 17.9% ± 2.4% / 57.9% ± 2.7% / 7.7% ± 1.6% / 13.8% ± 1.8% |
| 0.10 | None | 93.59% ± 0.90% | 31.29 ± 0.55 | 134.80 ± 5.85 | 0.47% ± 0.35% | 0.0% ± 0.0% / 1.3% ± 1.6% / 98.3% ± 1.4% / 0.4% ± 0.3% / 0.0% ± 0.0% |

For the 0%-malicious 400-round trials, the lifetimes (all 20 runs reached the
half-alive threshold) were 212.3 ± 10.2, 211.6 ± 12.1, 207.3 ± 11.5, and
243.8 ± 6.9 rounds for MAD floors 0.01, 0.03, 0.05, and 0.10 with
`abs_floor=0.6`; with no absolute guard they were 212.2 ± 12.1, 215.2 ± 14.8,
211.8 ± 13.3, and 244.0 ± 7.3 rounds, respectively.

For the 20%-malicious case, `mad_floor=0.03, abs_floor=0.6` is the best
balanced setting in this sweep (highest PDR among guarded floors, low FPR,
energy, and latency). `mad_floor=0.01, abs_floor=0.6` has a slightly longer
mean lifetime (289.9 vs 287.2 rounds); these small differences do not establish
a universal optimum.

### Distribution shift at round 50

The shift increases the congestion input/proxy by 0.2 for all alive nodes,
reduces honest-node PFR by 0.12 and increases its paid delay feature by 0.05;
malicious attack generation is unchanged. FPR before is averaged over rounds
1–49 and after over rounds 50–100. Values are means ± SD over 20 seeds.

| Malicious | Method | PDR | Energy/round | FPR before | FPR after |
|---:|---|---:|---:|---:|---:|
| 0% | CATES-PQC | 73.2% ± 4.8% | 34.44 ± 1.13 | 27.3% ± 2.9% | 27.2% ± 3.6% |
| 0% | Guarded MAD | 78.2% ± 2.0% | 28.37 ± 0.45 | 0.0% ± 0.0% | 0.0% ± 0.1% |
| 0% | Fixed thresholds | 78.2% ± 1.8% | 17.09 ± 0.35 | 0.0% ± 0.0% | 0.0% ± 0.0% |
| 0% | Fixed-trust routing | 78.4% ± 1.8% | 39.92 ± 0.16 | 0.0% ± 0.0% | 0.0% ± 0.0% |
| 20% | CATES-PQC | 72.9% ± 6.9% | 24.22 ± 1.09 | 9.7% ± 3.9% | 8.0% ± 3.7% |
| 20% | Guarded MAD | 74.1% ± 6.4% | 21.96 ± 0.42 | 0.0% ± 0.0% | 0.1% ± 0.3% |
| 20% | Fixed thresholds | 74.1% ± 6.4% | 14.87 ± 0.34 | 0.0% ± 0.0% | 0.0% ± 0.0% |
| 20% | Fixed-trust routing | 74.2% ± 5.5% | 46.86 ± 0.64 | 0.0% ± 0.0% | 0.0% ± 0.0% |

At 20% malicious, guarded MAD's paired PDR difference against fixed thresholds
was +0.04 percentage points (95% bootstrap CI -0.33 to +0.40 points,
Wilcoxon p=0.898); the PDR difference is not significant. Its post-shift FPR
was slightly higher and energy/latency were also
higher. Thus guarded MAD does not establish a PDR advantage over fixed
thresholds under this shift, although it reduces modeled energy substantially
versus unguarded CATES. The fixed-threshold method retained zero FPR and lower
energy in this scenario; the claim that guarded adaptive thresholds are
uniformly better than fixed thresholds therefore does not hold. More generally,
the simulations support trade-offs rather than a universal CATES win across
all metrics. `paired_stats.csv` contains paired 95% bootstrap
intervals (10,000 resamples) and Wilcoxon tests for the floor sweep and both
shift comparisons.

### Sensitivity sweeps

For the 20% constant-attack PQC-cost sweep, both PQC latency and energy scale
from their lightweight costs by the listed multiplier:

| Multiplier | PDR | Energy/round | Auth latency/round (ms) |
|---:|---:|---:|---:|
| 3× | 88.7% ± 7.6% | 23.72 ± 1.16 | 98.93 ± 6.09 |
| 5× | 88.1% ± 7.8% | 24.11 ± 1.22 | 101.37 ± 6.59 |
| 10× | 87.6% ± 7.9% | 24.37 ± 1.18 | 103.09 ± 6.48 |
| 20× | 86.3% ± 9.7% | 25.22 ± 1.30 | 107.79 ± 7.11 |

The lambda/threshold sweep tests all nine combinations of lambda 0.5, 0.7, 0.9
and k 1, 1.5, 2. At k=2, PDR is 88.0% ± 7.7%, 88.1% ± 7.8%, and 87.5% ± 8.5%
respectively; detection is 100.0% ± 0.0% at each lambda. The full matrix is in
`lambda_threshold_sweep_mean_std.csv`.

## Statistical comparison

`paired_stats.csv` contains per-seed CATES-minus-baseline paired differences
for PDR, energy/round, authentication latency, and lifetime, with percentile
95% bootstrap confidence intervals (10,000 resamples) and two-sided Wilcoxon
signed-rank p-values. At 20% constant attack for 100-round runs, CATES versus
Fixed Trust + Routing has PDR difference -1.24 percentage points (95% CI
-2.81 to +0.26 points, p=0.261); versus Traditional Trust-Based, it is +12.86
points (95% CI +10.95 to +14.98, p<0.001).

The `cates_no_routing` ablation disables quarantine as well as trust-aware
routing. This changes the active sender population, congestion inputs, and
energy/trust evolution; its roughly 43% detection rate is therefore not a
classifier-only comparison. In the inspected seed, the variants agreed on
detection through round 25 and began to diverge after their simulation inputs
separated.

## Model limitations

PQC authentication is represented by configurable latency and energy costs; it
does not call liboqs or implement/benchmark ML-DSA. The attacker is synthetic:
on-off attackers behave normally with probability `p_good` each round and
maliciously otherwise. Network topology, radio loss, and behavioral features
are simplified simulation models rather than deployed-device measurements.
