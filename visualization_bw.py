"""
visualization.py
------------------
Module: Publication-quality graph generation (Figures 1-6), saved as
300 DPI PNG files into the results/ directory, matching the IEEE
conference paper evaluation requirements.

All figures are rendered in black-and-white / grayscale (no color), using
distinct hatching patterns, line styles, and markers to distinguish the
four compared methods -- suitable for black-and-white print in an IEEE
conference paper.
"""

import os
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams.update({
    "figure.dpi": 100,
    "savefig.dpi": 300,
    "font.size": 11,
    "font.family": "serif",
    "axes.grid": True,
    "grid.alpha": 0.3,
    "axes.edgecolor": "black",
    "axes.facecolor": "white",
    "figure.facecolor": "white",
    "savefig.facecolor": "white",
})

METHOD_ORDER = ["No Security", "Always PQC", "Traditional Trust-Based", "CATES-PQC (Proposed)"]

# Grayscale shades (0 = black, 1 = white) -- kept distinct enough to read
# even without hatching, and paired with hatch patterns for print clarity.
METHOD_GRAYS = {
    "No Security": "0.85",
    "Always PQC": "0.55",
    "Traditional Trust-Based": "0.30",
    "CATES-PQC (Proposed)": "0.05",
}

METHOD_HATCHES = {
    "No Security": "",
    "Always PQC": "xx",
    "Traditional Trust-Based": "//",
    "CATES-PQC (Proposed)": "..",
}

# Line styles / markers for line plots (Figure 1, alive-fraction plot)
METHOD_LINESTYLES = {
    "No Security": (0, (1, 1)),        # dotted
    "Always PQC": (0, (5, 2)),         # dashed
    "Traditional Trust-Based": (0, (3, 1, 1, 1)),  # dash-dot
    "CATES-PQC (Proposed)": "solid",
}
METHOD_MARKERS = {
    "No Security": "o",
    "Always PQC": "x",
    "Traditional Trust-Based": "^",
    "CATES-PQC (Proposed)": "s",
}


def _ensure_dir(path):
    os.makedirs(path, exist_ok=True)


def fig1_trust_evolution(normal_history, malicious_history, out_dir):
    _ensure_dir(out_dir)
    plt.figure(figsize=(7, 5))
    plt.plot(normal_history, label="Normal node", color="black", linewidth=2,
              linestyle="solid")
    plt.plot(malicious_history, label="Malicious node", color="black", linewidth=2,
              linestyle=(0, (5, 2)))
    plt.xlabel("Simulation Round")
    plt.ylabel("Trust Score")
    plt.title("Figure 1: Trust Score Evolution (Normal vs Malicious Node)")
    plt.ylim(0, 1)
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "figure1_trust_evolution.png"), dpi=300)
    plt.close()


def _bar_comparison(summary_df, column, title, ylabel, filename, out_dir, pct=False):
    _ensure_dir(out_dir)
    df = summary_df.set_index("Method").reindex(METHOD_ORDER)
    values = df[column].values
    grays = [METHOD_GRAYS[m] for m in METHOD_ORDER]
    hatches = [METHOD_HATCHES[m] for m in METHOD_ORDER]

    plt.figure(figsize=(7.5, 5))
    bars = plt.bar(METHOD_ORDER, values, color=grays, edgecolor="black", linewidth=1.0)
    for bar, hatch in zip(bars, hatches):
        bar.set_hatch(hatch)
    for b, v in zip(bars, values):
        label = f"{v*100:.1f}%" if pct else f"{v:.2f}"
        plt.text(b.get_x() + b.get_width() / 2, b.get_height(), label,
                  ha="center", va="bottom", fontsize=9, color="black")
    plt.ylabel(ylabel)
    plt.title(title)
    plt.xticks(rotation=15, ha="right")
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, filename), dpi=300)
    plt.close()


def fig2_pdr(summary_df, out_dir):
    _bar_comparison(summary_df, "Packet Delivery Ratio",
                     "Figure 2: Packet Delivery Ratio Comparison",
                     "Packet Delivery Ratio", "figure2_pdr_comparison.png", out_dir, pct=True)


def fig3_energy(summary_df, out_dir):
    _bar_comparison(summary_df, "Avg Energy / Round",
                     "Figure 3: Energy Consumption Comparison",
                     "Avg Energy Consumed / Round (units)",
                     "figure3_energy_comparison.png", out_dir)


def fig4_latency(summary_df, out_dir):
    _bar_comparison(summary_df, "Avg Auth Latency (ms)",
                     "Figure 4: Authentication Latency Comparison",
                     "Avg Authentication Latency (ms)",
                     "figure4_latency_comparison.png", out_dir)


def fig5_detection(summary_df, out_dir):
    _bar_comparison(summary_df, "Attack Detection Rate",
                     "Figure 5: Attack Detection Rate Comparison",
                     "Attack Detection Rate", "figure5_detection_comparison.png",
                     out_dir, pct=True)


def fig6_lifetime(summary_df, out_dir):
    _bar_comparison(summary_df, "Network Lifetime (rounds)",
                     "Figure 6: Network Lifetime Comparison",
                     "Network Lifetime (rounds)", "figure6_lifetime_comparison.png", out_dir)


def fig_alive_fraction_over_time(method_dfs, out_dir):
    """Bonus supporting figure: alive-node fraction over rounds per method
    (useful evidence for the network-lifetime claim in the paper)."""
    _ensure_dir(out_dir)
    plt.figure(figsize=(7.5, 5))
    for method, df in method_dfs.items():
        plt.plot(df["round"], df["alive_fraction"], label=method,
                  color="black", linewidth=1.8,
                  linestyle=METHOD_LINESTYLES.get(method, "solid"),
                  marker=METHOD_MARKERS.get(method, None),
                  markevery=8, markersize=5, markerfacecolor="white")
    plt.xlabel("Simulation Round")
    plt.ylabel("Fraction of Alive Nodes")
    plt.title("Alive Node Fraction Over Time (Network Lifetime Evidence)")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "figure6b_alive_fraction_over_time.png"), dpi=300)
    plt.close()


def generate_all_figures(normal_trust_hist, malicious_trust_hist, summary_df,
                          method_dfs, out_dir):
    fig1_trust_evolution(normal_trust_hist, malicious_trust_hist, out_dir)
    fig2_pdr(summary_df, out_dir)
    fig3_energy(summary_df, out_dir)
    fig4_latency(summary_df, out_dir)
    fig5_detection(summary_df, out_dir)
    fig6_lifetime(summary_df, out_dir)
    fig_alive_fraction_over_time(method_dfs, out_dir)
