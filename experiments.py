"""Reproducible multi-seed simulation, ablation, and sensitivity experiments."""

import argparse
from concurrent.futures import ProcessPoolExecutor, as_completed
import os

import numpy as np
import pandas as pd
from scipy.stats import wilcoxon

import main as simulation
import visualization as viz


METRIC_COLUMNS = [
    "avg_pdr",
    "avg_energy_per_round",
    "avg_auth_latency_ms",
    "network_lifetime_rounds",
    "avg_detection_rate",
    "avg_false_positive_rate",
    "mean_time_to_detection_rounds",
    "malicious_nodes_detected",
    "time_to_detection_coverage",
    "avg_hop_count_delivered",
    "throughput_packets_per_round",
    "honest_share_excellent",
    "honest_share_trusted",
    "honest_share_suspicious",
    "honest_share_compromised",
    "honest_share_quarantined",
    "fpr_before_shift",
    "fpr_after_shift",
]
GROUP_COLUMNS = [
    "run_type", "method_key", "method", "malicious_ratio", "attack_mode",
    "pqc_cost_multiplier", "lambda_value", "threshold_k", "mad_floor",
    "abs_floor", "scenario",
]
PAIRED_METRICS = {
    "PDR": "avg_pdr",
    "Energy per round": "avg_energy_per_round",
    "Auth latency": "avg_auth_latency_ms",
    "Lifetime": "network_lifetime_rounds",
}


def _run_trial(task):
    method_key, seed, run_type, ratio, attack_mode, rounds, overrides, params = task
    collector, normal_trust, malicious_trust = simulation.run_method(
        method_key,
        seed=seed,
        num_rounds=rounds,
        malicious_ratio=ratio,
        attack_mode=attack_mode,
        overrides=overrides,
        verbose=False,
    )
    trial = {
        "run_type": run_type,
        "method_key": method_key,
        "method": simulation.METHOD_CONFIG[method_key]["label"],
        "malicious_ratio": ratio,
        "attack_mode": attack_mode,
        "seed": seed,
        "mad_floor": params.get(
            "mad_floor", overrides.get(
                "mad_floor", simulation.METHOD_CONFIG[method_key].get("mad_floor")
            )
        ),
        "abs_floor": params.get(
            "abs_floor", overrides.get(
                "abs_floor", simulation.METHOD_CONFIG[method_key].get("abs_floor")
            )
        ),
        "scenario": params.get("scenario", overrides.get("scenario")),
        "pqc_cost_multiplier": params.get("pqc_cost_multiplier"),
        "lambda_value": params.get("lambda_value"),
        "threshold_k": params.get("threshold_k"),
        **params,
        **collector.summary(),
    }
    trust = None
    if run_type == "main" and method_key == "cates_pqc" and ratio == 0.2:
        trust = {
            "seed": seed,
            "attack_mode": attack_mode,
            "normal": normal_trust,
            "malicious": malicious_trust,
            "thresholds": collector.threshold_history,
        }
    alive = None
    if run_type == "lifetime_400":
        alive = {
            "method": simulation.METHOD_CONFIG[method_key]["label"],
            "attack_mode": attack_mode,
            "seed": seed,
            "rounds": collector.to_dataframe()[
                ["round", "alive_fraction"]
            ].to_dict("records"),
        }
    return trial, trust, alive


def _summarize_trials(raw):
    grouped = raw.groupby(GROUP_COLUMNS, dropna=False)
    means = grouped[METRIC_COLUMNS].mean().add_suffix("_mean")
    stds = grouped[METRIC_COLUMNS].std(ddof=1).add_suffix("_std")
    counts = grouped.size().rename("n_seeds")
    not_reached = grouped["network_lifetime_rounds"].apply(
        lambda values: int(values.isna().sum())
    ).rename("lifetime_not_reached_count")
    return pd.concat([counts, not_reached, means, stds], axis=1).reset_index()


def _make_tasks(seeds, ratios, attack_modes):
    settings = simulation.CONFIG["experiment_settings"]
    tasks = []
    for mode in attack_modes:
        for ratio in ratios:
            for seed in seeds:
                for method in simulation.METHOD_ORDER:
                    tasks.append((
                        method, seed, "main", ratio, mode,
                        simulation.CONFIG["NUM_ROUNDS"], {}, {},
                    ))
        for seed in seeds:
            for method in simulation.METHOD_ORDER:
                tasks.append((
                    method, seed, "lifetime_400", 0.2, mode,
                    settings["lifetime_rounds"], {}, {},
                ))
    for seed in seeds:
        for multiplier in settings["pqc_cost_multipliers"]:
            costs = simulation.CONFIG["authentication_costs"]
            overrides = {"authentication_costs": {
                "pqc_latency_ms": costs["lightweight_latency_ms"] * multiplier,
                "pqc_energy": costs["lightweight_energy"] * multiplier,
            }}
            tasks.append((
                "cates_pqc", seed, "pqc_cost_sweep", 0.2, "constant",
                simulation.CONFIG["NUM_ROUNDS"], overrides,
                {"pqc_cost_multiplier": multiplier},
            ))
        for lam in settings["lambda_values"]:
            for k in settings["threshold_k_values"]:
                thresholds = {
                    "upper": [k, k / 2.0],
                    "lower": [k / 2.0, k],
                }
                tasks.append((
                    "cates_pqc", seed, "lambda_threshold_sweep", 0.2,
                    "constant", simulation.CONFIG["NUM_ROUNDS"],
                    {"lambda": lam, "threshold_multipliers": thresholds},
                    {"lambda_value": lam, "threshold_k": k},
                ))
    return tasks


def _paired_statistics(raw, output_path):
    rows = []
    seed_rng = np.random.default_rng(20261021)
    for run_type in ("main", "lifetime_400"):
        baseline_keys = ["malicious_ratio", "attack_mode"]
        group_cols = [c for c in baseline_keys if c in raw.columns]
        cates = raw[
            (raw["run_type"] == run_type) & (raw["method_key"] == "cates_pqc")
        ]
        for baseline in ("trust_fixed_routing", "trust_fixed"):
            controls = raw[
                (raw["run_type"] == run_type) & (raw["method_key"] == baseline)
            ]
            for group_key, cates_group in cates.groupby(group_cols, dropna=False):
                if not isinstance(group_key, tuple):
                    group_key = (group_key,)
                filters = dict(zip(group_cols, group_key))
                controls_group = controls
                for column, value in filters.items():
                    controls_group = controls_group[controls_group[column] == value]
                for metric_label, column in PAIRED_METRICS.items():
                    if metric_label == "Lifetime" and run_type != "lifetime_400":
                        continue
                    paired = cates_group[["seed", column]].merge(
                        controls_group[["seed", column]],
                        on="seed", suffixes=("_cates", "_baseline"),
                    ).dropna()
                    differences = (
                        paired[f"{column}_cates"] - paired[f"{column}_baseline"]
                    ).to_numpy(dtype=float)
                    if not differences.size:
                        continue
                    if differences.size == 1:
                        low = high = float(differences[0])
                    else:
                        bootstrap = seed_rng.choice(
                            differences,
                            size=(simulation.CONFIG["experiment_settings"][
                                "bootstrap_resamples"
                            ], differences.size),
                            replace=True,
                        ).mean(axis=1)
                        low, high = np.percentile(bootstrap, [2.5, 97.5])
                    p_value = (
                        1.0 if np.all(differences == 0) else
                        float(wilcoxon(differences, alternative="two-sided").pvalue)
                    )
                    rows.append({
                        "run_type": run_type,
                        **filters,
                        "cates_method": "cates_pqc",
                        "baseline_method": baseline,
                        "metric": metric_label,
                        "n_seeds": int(differences.size),
                        "mean_paired_difference": float(differences.mean()),
                        "ci95_low": float(low),
                        "ci95_high": float(high),
                        "wilcoxon_p_value": p_value,
                    })
        guarded = raw[
            (raw["run_type"] == run_type)
            & (raw["method_key"] == "cates_pqc_guarded")
        ]
        for baseline in ("cates_fixed_threshold", "cates_pqc"):
            controls = raw[
                (raw["run_type"] == run_type) & (raw["method_key"] == baseline)
            ]
            for group_key, guarded_group in guarded.groupby(
                    group_cols, dropna=False):
                if not isinstance(group_key, tuple):
                    group_key = (group_key,)
                filters = dict(zip(group_cols, group_key))
                controls_group = controls
                for column, value in filters.items():
                    controls_group = controls_group[controls_group[column] == value]
                for metric_label, column in PAIRED_METRICS.items():
                    if metric_label == "Lifetime" and run_type != "lifetime_400":
                        continue
                    paired = guarded_group[["seed", column]].merge(
                        controls_group[["seed", column]],
                        on="seed", suffixes=("_variant", "_baseline"),
                    ).dropna()
                    differences = (
                        paired[f"{column}_variant"]
                        - paired[f"{column}_baseline"]
                    ).to_numpy(dtype=float)
                    if not differences.size:
                        continue
                    bootstrap = seed_rng.choice(
                        differences,
                        size=(simulation.CONFIG["experiment_settings"][
                            "bootstrap_resamples"
                        ], differences.size),
                        replace=True,
                    ).mean(axis=1)
                    rows.append({
                        "run_type": run_type,
                        **filters,
                        "cates_method": "cates_pqc_guarded",
                        "baseline_method": baseline,
                        "metric": metric_label,
                        "n_seeds": int(differences.size),
                        "mean_paired_difference": float(differences.mean()),
                        "ci95_low": float(np.percentile(bootstrap, 2.5)),
                        "ci95_high": float(np.percentile(bootstrap, 97.5)),
                        "wilcoxon_p_value": (
                            1.0 if np.all(differences == 0) else
                            float(wilcoxon(
                                differences, alternative="two-sided"
                            ).pvalue)
                        ),
                    })
    pd.DataFrame(rows).to_csv(output_path, index=False)


def _trust_summary(histories):
    records = []
    if not histories:
        return pd.DataFrame()
    for mode in ("constant", "on_off"):
        mode_histories = [item for item in histories if item["attack_mode"] == mode]
        if not mode_histories:
            continue
        for group in ("normal", "malicious"):
            matrix = np.asarray([item[group] for item in mode_histories], dtype=float)
            for round_index in range(matrix.shape[1]):
                records.append({
                    "round": round_index + 1,
                    "group": group,
                    "attack_mode": mode,
                    "mean": float(np.nanmean(matrix[:, round_index])),
                    "std": float(np.nanstd(matrix[:, round_index], ddof=1)),
                })
        if mode == "constant":
            threshold_matrix = np.asarray(
                [item["thresholds"] for item in mode_histories], dtype=float
            )
            threshold_mean = np.nanmean(threshold_matrix, axis=0)
            boundary_names = (
                "median", "upper_1mad", "lower_1mad", "upper_2mad", "lower_2mad"
            )
            boundary_values = np.column_stack((
                threshold_mean[:, 0],
                threshold_mean[:, 0] + threshold_mean[:, 1],
                threshold_mean[:, 0] - threshold_mean[:, 1],
                threshold_mean[:, 0] + 2 * threshold_mean[:, 1],
                threshold_mean[:, 0] - 2 * threshold_mean[:, 1],
            ))
            for record in records:
                if record["attack_mode"] == mode:
                    record.update(dict(zip(
                        boundary_names, boundary_values[record["round"] - 1]
                    )))
    return pd.DataFrame(records)


def _alive_summary(histories):
    if not histories:
        return pd.DataFrame()
    frame = pd.concat([
        pd.DataFrame(item["rounds"]).assign(
            method=item["method"], attack_mode=item["attack_mode"], seed=item["seed"]
        )
        for item in histories
    ], ignore_index=True)
    return frame.groupby(
        ["method", "attack_mode", "round"]
    )["alive_fraction"].agg(mean="mean", std="std").reset_index()


def run_experiments(seeds=None, ratios=None, attack_modes=None, output_dir=None,
                    verbose=True, workers=None):
    settings = simulation.CONFIG["experiment_settings"]
    seeds = list(settings["seeds"] if seeds is None else seeds)
    ratios = list(settings["malicious_ratios"] if ratios is None else ratios)
    attack_modes = list(
        settings["attack_modes"] if attack_modes is None else attack_modes
    )
    output_dir = output_dir or simulation.RESULTS_DIR
    os.makedirs(output_dir, exist_ok=True)
    simulation.write_config(output_dir, print_config=verbose)

    tasks = _make_tasks(seeds, ratios, attack_modes)
    max_workers = workers or min(2, os.cpu_count() or 1)
    trials, trust_histories, alive_histories = [], [], []
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_run_trial, task) for task in tasks]
        for completed, future in enumerate(as_completed(futures), start=1):
            trial, trust, alive = future.result()
            trials.append(trial)
            if trust is not None:
                trust_histories.append(trust)
            if alive is not None:
                alive_histories.append(alive)
            if verbose:
                print(f"\rExperiment sweep: {completed}/{len(tasks)}", end="")
    if verbose:
        print()

    raw = pd.DataFrame(trials)
    raw_path = os.path.join(output_dir, "experiment_raw.csv")
    raw.to_csv(raw_path, index=False)
    mean_std = _summarize_trials(raw)
    summary_path = os.path.join(output_dir, "experiment_mean_std.csv")
    mean_std.to_csv(summary_path, index=False)

    paired_path = os.path.join(output_dir, "paired_stats.csv")
    _paired_statistics(raw, paired_path)
    cost_raw = raw[raw["run_type"] == "pqc_cost_sweep"].copy()
    cost_summary = _summarize_trials(cost_raw)
    cost_raw.to_csv(os.path.join(output_dir, "pqc_cost_sweep_raw.csv"), index=False)
    cost_summary.to_csv(
        os.path.join(output_dir, "pqc_cost_sweep_mean_std.csv"), index=False
    )
    threshold_raw = raw[raw["run_type"] == "lambda_threshold_sweep"].copy()
    threshold_summary = _summarize_trials(threshold_raw)
    threshold_raw.to_csv(
        os.path.join(output_dir, "lambda_threshold_sweep_raw.csv"), index=False
    )
    threshold_summary.to_csv(
        os.path.join(output_dir, "lambda_threshold_sweep_mean_std.csv"), index=False
    )

    trust_data = _trust_summary(trust_histories)
    trust_data.to_csv(
        os.path.join(output_dir, "trust_evolution_mean_std.csv"), index=False
    )
    alive_data = _alive_summary(alive_histories)
    alive_data.to_csv(
        os.path.join(output_dir, "lifetime_alive_fraction_mean_std.csv"), index=False
    )
    viz.generate_experiment_figures(
        mean_std, trust_data, alive_data, output_dir,
        cost_summary=cost_summary, threshold_summary=threshold_summary,
    )
    if verbose:
        print(f"Saved {len(raw)} seeded trials to {output_dir}.")
    return raw, mean_std, trust_data, alive_data


def _guard_shift_tasks(seeds):
    settings = simulation.CONFIG["experiment_settings"]
    tasks = []
    for ratio in (0.0, 0.2):
        for mad_floor in settings["mad_floors"]:
            for abs_floor in settings["abs_floors"]:
                for seed in seeds:
                    tasks.append((
                        "cates_pqc", seed, "mad_floor_sweep", ratio, "constant",
                        simulation.CONFIG["NUM_ROUNDS"],
                        {"mad_floor": mad_floor, "abs_floor": abs_floor},
                        {"mad_floor": mad_floor, "abs_floor": abs_floor},
                    ))
                    tasks.append((
                        "cates_pqc", seed, "mad_floor_lifetime", ratio,
                        "constant", settings["lifetime_rounds"],
                        {"mad_floor": mad_floor, "abs_floor": abs_floor},
                        {"mad_floor": mad_floor, "abs_floor": abs_floor},
                    ))
    for ratio in (0.0, 0.2):
        for method in (
            "cates_pqc", "cates_pqc_guarded",
            "cates_fixed_threshold", "trust_fixed_routing",
        ):
            for seed in seeds:
                tasks.append((
                    method, seed, "distribution_shift", ratio, "constant",
                    simulation.CONFIG["NUM_ROUNDS"], {"scenario": "shift"},
                    {"scenario": "shift"},
                ))
    return tasks


def _supplementary_paired_rows(sweep_raw, shift_raw, output_dir):
    path = os.path.join(output_dir, "paired_stats.csv")
    existing = pd.read_csv(path) if os.path.exists(path) else pd.DataFrame()
    if not existing.empty and "run_type" in existing:
        existing = existing[~existing["run_type"].isin(
            ("mad_floor_sweep", "mad_floor_lifetime", "distribution_shift")
        )]
    reference_path = os.path.join(output_dir, "experiment_raw.csv")
    references = pd.read_csv(reference_path) if os.path.exists(reference_path) else pd.DataFrame()
    rng = np.random.default_rng(20261021)
    additions = []

    def append_comparison(cates_rows, baseline_rows, baseline_method, run_type,
                          filters, metric_pairs):
        for label, metric in metric_pairs:
            paired = cates_rows[["seed", metric]].merge(
                baseline_rows[["seed", metric]], on="seed",
                suffixes=("_variant", "_baseline"),
            ).dropna()
            differences = (
                paired[f"{metric}_variant"] - paired[f"{metric}_baseline"]
            ).to_numpy(dtype=float)
            if not differences.size:
                continue
            bootstrap = rng.choice(
                differences,
                size=(simulation.CONFIG["experiment_settings"][
                    "bootstrap_resamples"
                ], differences.size),
                replace=True,
            ).mean(axis=1)
            p_value = (
                1.0 if np.all(differences == 0) else
                float(wilcoxon(differences, alternative="two-sided").pvalue)
            )
            additions.append({
                "run_type": run_type,
                **filters,
                "cates_method": str(cates_rows["method_key"].iloc[0]),
                "baseline_method": baseline_method,
                "metric": label,
                "n_seeds": len(differences),
                "mean_paired_difference": float(differences.mean()),
                "ci95_low": float(np.percentile(bootstrap, 2.5)),
                "ci95_high": float(np.percentile(bootstrap, 97.5)),
                "wilcoxon_p_value": p_value,
            })

    if not references.empty:
        for run_type, source_type in (
            ("mad_floor_sweep", "main"),
            ("mad_floor_lifetime", "lifetime_400"),
        ):
            variants = sweep_raw[sweep_raw["run_type"] == run_type]
            refs = references[references["run_type"] == source_type]
            for (ratio, mad_floor, abs_floor), group in variants.groupby(
                    ["malicious_ratio", "mad_floor", "abs_floor"],
                    dropna=False):
                matching = refs[
                    (refs["malicious_ratio"] == ratio)
                    & (refs["attack_mode"] == "constant")
                ]
                if matching.empty:
                    continue
                method_pairs = (
                    PAIRED_METRICS.items()
                    if run_type == "mad_floor_lifetime"
                    else [(name, column) for name, column in PAIRED_METRICS.items()
                          if name != "Lifetime"]
                )
                for baseline in ("cates_pqc", "cates_fixed_threshold"):
                    baseline_rows = matching[matching["method_key"] == baseline]
                    if baseline_rows.empty:
                        continue
                    filters = {
                        "malicious_ratio": ratio, "attack_mode": "constant",
                        "mad_floor": mad_floor, "abs_floor": abs_floor,
                    }
                    append_comparison(
                        group, baseline_rows, baseline, run_type, filters, method_pairs
                    )

    if not shift_raw.empty:
        for ratio in (0.0, 0.2):
            group = shift_raw[shift_raw["malicious_ratio"] == ratio]
            for method in ("cates_pqc", "cates_pqc_guarded"):
                variant = group[group["method_key"] == method]
                for baseline in ("cates_fixed_threshold", "cates_pqc"):
                    controls = group[group["method_key"] == baseline]
                    if variant.empty or controls.empty:
                        continue
                    append_comparison(
                        variant, controls, baseline, "distribution_shift",
                        {"malicious_ratio": ratio, "attack_mode": "constant",
                         "scenario": "shift"},
                        [(name, column) for name, column in PAIRED_METRICS.items()
                         if name != "Lifetime"],
                    )
    combined = pd.concat([existing, pd.DataFrame(additions)], ignore_index=True)
    combined.to_csv(path, index=False)


def run_guard_shift_experiments(seeds=None, output_dir=None, workers=None,
                                verbose=True):
    settings = simulation.CONFIG["experiment_settings"]
    seeds = list(settings["seeds"] if seeds is None else seeds)
    output_dir = output_dir or simulation.RESULTS_DIR
    os.makedirs(output_dir, exist_ok=True)
    simulation.write_config(output_dir, print_config=verbose)
    tasks = _guard_shift_tasks(seeds)
    max_workers = workers or min(2, os.cpu_count() or 1)
    trials = []
    with ProcessPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(_run_trial, task) for task in tasks]
        for completed, future in enumerate(as_completed(futures), start=1):
            trial, _, _ = future.result()
            trials.append(trial)
            if verbose:
                print(f"\rGuard/shift sweep: {completed}/{len(tasks)}", end="")
    if verbose:
        print()
    raw = pd.DataFrame(trials)
    sweep_raw = raw[raw["run_type"].isin(
        ("mad_floor_sweep", "mad_floor_lifetime")
    )].copy()
    shift_raw = raw[raw["run_type"] == "distribution_shift"].copy()
    sweep_raw.to_csv(os.path.join(output_dir, "mad_floor_sweep_raw.csv"), index=False)
    _summarize_trials(sweep_raw).to_csv(
        os.path.join(output_dir, "mad_floor_sweep_mean_std.csv"), index=False
    )
    shift_raw.to_csv(
        os.path.join(output_dir, "distribution_shift_raw.csv"), index=False
    )
    shift_summary = _summarize_trials(shift_raw)
    shift_summary.to_csv(
        os.path.join(output_dir, "distribution_shift_mean_std.csv"), index=False
    )
    viz.fig_shift_fpr(shift_summary, output_dir)
    _supplementary_paired_rows(sweep_raw, shift_raw, output_dir)
    if verbose:
        print(f"Saved {len(raw)} guard/shift trials to {output_dir}.")
    return sweep_raw, shift_raw, shift_summary


def main():
    settings = simulation.CONFIG["experiment_settings"]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", type=int, default=len(settings["seeds"]))
    parser.add_argument("--seed-start", type=int, default=settings["seeds"][0])
    parser.add_argument("--ratios", type=float, nargs="+",
                        default=settings["malicious_ratios"])
    parser.add_argument("--attack-modes", nargs="+", choices=["constant", "on_off"],
                        default=settings["attack_modes"])
    parser.add_argument("--output-dir", default=simulation.RESULTS_DIR)
    parser.add_argument("--workers", type=int, default=min(2, os.cpu_count() or 1))
    parser.add_argument("--guard-shift-only", action="store_true",
                        help="Run MAD/absolute-floor and distribution-shift experiments")
    args = parser.parse_args()
    if args.guard_shift_only:
        run_guard_shift_experiments(
            range(args.seed_start, args.seed_start + args.seeds),
            args.output_dir, workers=args.workers,
        )
        return
    run_experiments(
        range(args.seed_start, args.seed_start + args.seeds),
        args.ratios, args.attack_modes, args.output_dir, workers=args.workers,
    )


if __name__ == "__main__":
    main()
