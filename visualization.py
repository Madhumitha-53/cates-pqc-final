"""Publication figures from multi-seed mean and standard-deviation results."""

import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd


plt.rcParams.update({
    "figure.dpi": 100,
    "savefig.dpi": 300,
    "font.size": 10,
    "font.family": "serif",
    "axes.grid": True,
    "grid.alpha": 0.3,
})


def _ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def _save(fig, out_dir, filename):
    _ensure_dir(out_dir)
    fig.tight_layout()
    fig.savefig(os.path.join(out_dir, filename), dpi=300, bbox_inches="tight")
    plt.close(fig)


def _primary_summary(mean_std):
    frame = mean_std[
        (mean_std["run_type"] == "main")
        & (mean_std["malicious_ratio"] == 0.2)
        & (mean_std["attack_mode"] == "constant")
    ]
    return frame.set_index("method")


def _bar(summary, mean_column, std_column, ylabel, filename, out_dir,
         methods=None, percent=False):
    available = summary.dropna(subset=[mean_column])
    if methods is not None:
        available = available.reindex(methods).dropna(subset=[mean_column])
    labels = available.index.tolist()
    means = available[mean_column].to_numpy(dtype=float)
    errors = available[std_column].fillna(0).to_numpy(dtype=float)
    fig, ax = plt.subplots(figsize=(max(8, len(labels) * 1.15), 5))
    positions = np.arange(len(labels))
    bars = ax.bar(
        positions, means, yerr=errors, capsize=4, color=plt.cm.tab10(
            np.arange(len(labels)) % 10
        ), edgecolor="black", linewidth=0.5,
    )
    for bar, value in zip(bars, means):
        text = f"{value * 100:.1f}%" if percent else f"{value:.2f}"
        ax.annotate(text, (bar.get_x() + bar.get_width() / 2, bar.get_height()),
                    xytext=(0, 4), textcoords="offset points",
                    ha="center", va="bottom", fontsize=8)
    ax.set_ylabel(ylabel)
    ax.set_xticks(positions, labels, rotation=25, ha="right")
    _save(fig, out_dir, filename)


def fig1_trust_evolution(trust_summary, out_dir):
    fig, axes = plt.subplots(1, 2, figsize=(13, 5))
    styles = {
        "normal": ("#247a3c", "Normal nodes"),
        "malicious": ("#bd3030", "Malicious nodes"),
    }
    for ax, mode in zip(axes, ("constant", "on_off")):
        mode_summary = trust_summary[trust_summary["attack_mode"] == mode]
        for group, (color, label) in styles.items():
            values = mode_summary[mode_summary["group"] == group]
            x = values["round"].to_numpy()
            mean = values["mean"].to_numpy()
            std = values["std"].fillna(0).to_numpy()
            ax.plot(x, mean, color=color, linewidth=2, label=label)
            ax.fill_between(x, mean - std, mean + std, color=color, alpha=0.18)
        if mode == "constant":
            thresholds = mode_summary[mode_summary["group"] == "normal"]
            for column, label, style in (
                ("median", "Median", "--"),
                ("upper_1mad", "Median + MAD", ":"),
                ("lower_1mad", "Median - MAD", ":"),
                ("upper_2mad", "Median + 2 MAD", "-."),
                ("lower_2mad", "Median - 2 MAD", "-."),
            ):
                if column in thresholds:
                    ax.plot(thresholds["round"], thresholds[column],
                            color="#555555", linestyle=style,
                            linewidth=0.9, label=label)
        if mode == "on_off":
            malicious = mode_summary[mode_summary["group"] == "malicious"]["mean"]
            ax.set_ylim(max(0.0, float(malicious.min()) - 0.03),
                        min(1.0, float(malicious.max()) + 0.03))
        else:
            ax.set_ylim(0, 1)
        title = f"{mode.replace('_', '-').title()} attack"
        ax.set_title(f"{title} (zoomed y-axis)" if mode == "on_off" else title)
        ax.set_xlabel("Round")
        ax.legend(fontsize=8)
    axes[0].set_ylabel("Mean trust")
    _save(fig, out_dir, "figure1_trust_evolution.png")


def _comparison_bars(mean_std, out_dir):
    summary = _primary_summary(mean_std)
    _bar(summary, "avg_pdr_mean", "avg_pdr_std", "Packet delivery ratio",
         "figure2_pdr_comparison.png", out_dir, percent=True)
    _bar(summary, "avg_energy_per_round_mean", "avg_energy_per_round_std",
         "Energy per round (units)", "figure3_energy_comparison.png", out_dir)
    _bar(summary, "avg_auth_latency_ms_mean", "avg_auth_latency_ms_std",
         "Authentication latency (ms)", "figure4_latency_comparison.png", out_dir)
    _bar(summary, "avg_detection_rate_mean", "avg_detection_rate_std",
         "Detection rate", "figure5_detection_comparison.png", out_dir,
         percent=True)

    lifetime = mean_std[
        (mean_std["run_type"] == "lifetime_400")
        & (mean_std["malicious_ratio"] == 0.2)
        & (mean_std["attack_mode"] == "constant")
    ].set_index("method")
    _bar(lifetime, "network_lifetime_rounds_mean",
         "network_lifetime_rounds_std", "Lifetime (rounds)",
         "figure6_lifetime_comparison.png", out_dir)


def fig_pdr_vs_malicious(mean_std, out_dir):
    frame = mean_std[mean_std["run_type"] == "main"]
    modes = [mode for mode in ("constant", "on_off")
             if mode in set(frame["attack_mode"])]
    fig, axes = plt.subplots(1, max(1, len(modes)), figsize=(7 * max(1, len(modes)), 5),
                             squeeze=False)
    methods = list(dict.fromkeys(frame["method"].tolist()))
    colors = plt.cm.tab10(np.arange(len(methods)) % 10)
    for ax, mode in zip(axes[0], modes):
        mode_frame = frame[frame["attack_mode"] == mode]
        for method, color in zip(methods, colors):
            values = mode_frame[mode_frame["method"] == method].sort_values(
                "malicious_ratio"
            )
            ax.errorbar(
                values["malicious_ratio"] * 100,
                values["avg_pdr_mean"],
                yerr=values["avg_pdr_std"].fillna(0),
                marker="o", capsize=3, linewidth=1.5, color=color, label=method,
            )
        ax.set_xlabel("Malicious nodes (%)")
        ax.set_ylabel("Packet delivery ratio")
        ax.set_xticks(sorted(mode_frame["malicious_ratio"].unique() * 100))
        ax.legend(fontsize=7)
    _save(fig, out_dir, "figure7_pdr_vs_malicious.png")


def fig_ablation(mean_std, out_dir):
    focus = [
        "CATES-PQC (Proposed)",
        "CATES-PQC (Guarded MAD)",
        "CATES (No Routing/Quarantine)",
        "CATES (No Cache)",
        "CATES (Fixed Weights)",
        "CATES (Fixed Thresholds)",
        "Traditional Trust-Based",
        "Fixed Trust + Cache",
        "Fixed Trust + Routing",
    ]
    summary = _primary_summary(mean_std)
    _bar(summary, "avg_pdr_mean", "avg_pdr_std", "Packet delivery ratio",
         "figure8_ablation_pdr.png", out_dir, methods=focus, percent=True)


def fig_alive_fraction_over_time(alive_summary, out_dir):
    frame = alive_summary[alive_summary["attack_mode"] == "constant"]
    fig, ax = plt.subplots(figsize=(8, 5))
    for method, values in frame.groupby("method"):
        values = values.sort_values("round")
        x = values["round"].to_numpy()
        mean = values["mean"].to_numpy()
        std = values["std"].fillna(0).to_numpy()
        ax.plot(x, mean, label=method, linewidth=1.5)
        ax.fill_between(x, mean - std, mean + std, alpha=0.1)
    ax.axhline(0.5, color="black", linestyle="--", linewidth=1)
    ax.set_xlabel("Round")
    ax.set_ylabel("Alive-node fraction")
    ax.legend(fontsize=7)
    _save(fig, out_dir, "figure6b_alive_fraction_over_time.png")


def fig_pqc_cost_sensitivity(summary, out_dir):
    values = summary.sort_values("pqc_cost_multiplier")
    x = values["pqc_cost_multiplier"].to_numpy()
    fig, axes = plt.subplots(1, 3, figsize=(13, 4))
    for ax, metric, ylabel in zip(
        axes,
        ("avg_pdr", "avg_energy_per_round", "avg_auth_latency_ms"),
        ("PDR", "Energy per round", "Auth latency (ms)"),
    ):
        ax.errorbar(
            x, values[f"{metric}_mean"], yerr=values[f"{metric}_std"].fillna(0),
            marker="o", capsize=4,
        )
        ax.set_xlabel("PQC cost multiplier vs lightweight")
        ax.set_ylabel(ylabel)
        ax.set_xticks(x)
    _save(fig, out_dir, "figure9_pqc_cost_sensitivity.png")


def fig_lambda_threshold_sensitivity(summary, out_dir):
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    for ax, metric, title in zip(
        axes, ("avg_pdr", "avg_detection_rate"), ("PDR", "Detection rate")
    ):
        pivot = summary.pivot(
            index="lambda_value", columns="threshold_k", values=f"{metric}_mean"
        ).sort_index().sort_index(axis=1)
        matrix = pivot.to_numpy(dtype=float)
        image = ax.imshow(matrix, aspect="auto", origin="lower", cmap="viridis")
        ax.set_xticks(np.arange(len(pivot.columns)), pivot.columns)
        ax.set_yticks(np.arange(len(pivot.index)), pivot.index)
        ax.set_xlabel("Threshold multiplier k")
        ax.set_ylabel("Trust smoothing lambda")
        ax.set_title(title)
        for row in range(matrix.shape[0]):
            for col in range(matrix.shape[1]):
                ax.text(col, row, f"{matrix[row, col]:.2f}",
                        ha="center", va="center", color="white")
        fig.colorbar(image, ax=ax)
    _save(fig, out_dir, "figure10_lambda_threshold_sensitivity.png")


def fig_shift_fpr(summary, out_dir):
    methods = [
        ("CATES-PQC (Proposed)", "CATES"),
        ("CATES-PQC (Guarded MAD)", "Guarded MAD"),
        ("CATES (Fixed Thresholds)", "Fixed thresholds"),
        ("Fixed Trust + Routing", "Fixed-trust routing"),
    ]
    fig, axes = plt.subplots(1, 2, figsize=(12, 5), sharey=True)
    width = 0.34
    for ax, ratio in zip(axes, (0.0, 0.2)):
        values = summary[summary["malicious_ratio"] == ratio]
        x = np.arange(len(methods))
        for offset, phase, color in (
            (-width / 2, "before", "#4c78a8"),
            (width / 2, "after", "#f58518"),
        ):
            means = []
            errors = []
            for method, _ in methods:
                row = values[values["method"] == method]
                means.append(
                    float(row[f"fpr_{phase}_shift_mean"].iloc[0])
                    if not row.empty else np.nan
                )
                errors.append(
                    float(row[f"fpr_{phase}_shift_std"].fillna(0).iloc[0])
                    if not row.empty else 0.0
                )
            ax.bar(
                x + offset, means, width, yerr=errors, capsize=3,
                color=color, label=f"Rounds {'< 50' if phase == 'before' else '≥ 50'}",
            )
        ax.set_title(f"{ratio:.0%} malicious")
        ax.set_xticks(x, [label for _, label in methods], rotation=20, ha="right")
        ax.set_ylim(bottom=0)
        ax.set_ylabel("False-positive rate")
        ax.legend(fontsize=8)
    _save(fig, out_dir, "figure11_shift_fpr_before_after.png")


def generate_experiment_figures(mean_std, trust_summary, alive_summary, out_dir,
                                cost_summary=None, threshold_summary=None):
    if not trust_summary.empty:
        fig1_trust_evolution(trust_summary, out_dir)
    _comparison_bars(mean_std, out_dir)
    fig_pdr_vs_malicious(mean_std, out_dir)
    fig_ablation(mean_std, out_dir)
    fig_alive_fraction_over_time(alive_summary, out_dir)
    if cost_summary is not None and not cost_summary.empty:
        fig_pqc_cost_sensitivity(cost_summary, out_dir)
    if threshold_summary is not None and not threshold_summary.empty:
        fig_lambda_threshold_sensitivity(threshold_summary, out_dir)
