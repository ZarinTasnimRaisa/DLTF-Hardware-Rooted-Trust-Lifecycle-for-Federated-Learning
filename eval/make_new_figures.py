"""
make_new_figures.py -- turn the new CSVs into figures for the paper.

The paper currently carries two figures (the architecture diagram and the trust
trajectories) and five tables. The three newest results are all tables, and two
of them make a much stronger visual argument than a numeric one:

  fig_aggregator.pdf   the Krum collapse. A table row reading 0.053 is a number;
                       a bar chart showing Krum alone falling BELOW plain
                       averaging, then being restored above it, is the whole
                       composition argument in one glance. This is the strongest
                       new result in the paper and it deserves the figure slot.

  fig_m3.pdf           M3 exposure windows. Shows at once that M3 matters for a
                       single adversary and is irrelevant against two, which is
                       the nuance the prose has to work hard to convey.

  fig_scale.pdf        margin and honest false-positive rate against federation
                       size, if exp_scale.py has been run.

  fig_real_mnist.pdf   accuracy per round on real MNIST, layer on versus off,
                       if exp_real_mnist.py has been run.

Only figures whose CSV exists are produced, so run it after whichever
experiments you have completed.

Style matches the existing figures: matplotlib defaults, no seaborn, no custom
colour cycle, sized for a single ACM column at 0.82 width.

Run:
    python -m eval.make_new_figures --results results/ --out figs/
"""

import os
import csv
import argparse
import statistics as st

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

COL_W = 3.3          # ACM sigconf column, inches
plt.rcParams.update({"font.size": 8, "axes.grid": True,
                     "grid.alpha": 0.3, "figure.dpi": 200})


def _read(path):
    if not os.path.exists(path):
        return None
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def _save(fig, out, name):
    os.makedirs(out, exist_ok=True)
    for ext in ("pdf", "png"):
        fig.savefig(os.path.join(out, "%s.%s" % (name, ext)),
                    bbox_inches="tight")
    plt.close(fig)
    print("wrote %s/%s.pdf" % (out, name))


# --------------------------------------------------------------------------

def fig_aggregator(rows, out):
    """Grouped bars: for each rule, accuracy without and with the layer."""
    agg = {}
    for r in rows:
        key = (r["aggregator"], r["attack"], r["defense"])
        agg.setdefault(key, []).append(float(r["final_accuracy"]))

    rules = ["fedavg", "trimmed_mean", "krum"]
    label = {"fedavg": "Avg", "trimmed_mean": "Trim", "krum": "Krum"}
    attacks = [a for a in ("poison", "sleeper", "sybil")
               if any(k[1] == a for k in agg)]

    fig, axes = plt.subplots(1, len(attacks),
                             figsize=(COL_W, 1.9), sharey=True)
    if len(attacks) == 1:
        axes = [axes]

    for ax, attack in zip(axes, attacks):
        off = [st.mean(agg.get((r, attack, "plain"), [0])) for r in rules]
        on = [st.mean(agg.get((r, attack, "dltf"), [0])) for r in rules]
        x = range(len(rules))
        ax.bar([i - 0.2 for i in x], off, 0.4, label="no layer",
               color="0.75", edgecolor="0.3", linewidth=0.5)
        ax.bar([i + 0.2 for i in x], on, 0.4, label="+DLTF",
               color="0.25", edgecolor="0.1", linewidth=0.5)
        ax.set_xticks(list(x))
        ax.set_xticklabels([label[r] for r in rules], fontsize=6.5)
        ax.set_title(attack, fontsize=8)
        ax.set_ylim(0, 0.95)
    axes[0].set_ylabel("final accuracy")
    axes[0].legend(fontsize=6, loc="upper left", framealpha=0.95,
                   handlelength=1.0, borderpad=0.3, labelspacing=0.2)
    _save(fig, out, "fig_aggregator")


def fig_m3(rows, out):
    """Exposure window with M3 on and off, for one and two adversaries."""
    fig, ax = plt.subplots(figsize=(COL_W, 1.8))
    onset = {"sleeper": 10, "poison": 5}

    labels, on_v, off_v = [], [], []
    for r in rows:
        att, n = r["attack"], int(r["n_attackers"])
        mean_rnd = float(r["mean_sanction_round"])
        exposure = mean_rnd - onset.get(att, 0)
        key = "%s, %d adv" % (att, n)
        if r["m3"] == "on":
            labels.append(key)
            on_v.append(exposure)
        else:
            off_v.append(exposure)

    x = range(len(labels))
    ax.bar([i - 0.2 for i in x], on_v, 0.4, label="M3 on",
           color="0.25", edgecolor="0.1", linewidth=0.5)
    ax.bar([i + 0.2 for i in x], off_v, 0.4, label="M3 off",
           color="0.75", edgecolor="0.3", linewidth=0.5)
    ax.set_xticks(list(x))
    ax.set_xticklabels(labels, rotation=20, ha="right", fontsize=6)
    ax.set_ylabel("exposure (rounds)")
    ax.legend(fontsize=6)
    _save(fig, out, "fig_m3")


def fig_scale(rows, out):
    fig, ax = plt.subplots(figsize=(COL_W, 1.8))
    ax2 = ax.twinx()
    for attack in sorted({r["attack"] for r in rows}):
        sub = sorted((r for r in rows if r["attack"] == attack),
                     key=lambda r: int(r["clients"]))
        n = [int(r["clients"]) for r in sub]
        ax.plot(n, [float(r["margin"]) for r in sub], marker="o",
                markersize=3, label="margin, %s" % attack)
        ax2.plot(n, [float(r["honest_ban_rate"]) for r in sub], marker="s",
                 markersize=3, linestyle="--", alpha=0.6)
    ax.set_xlabel("federation size")
    ax.set_ylabel("accuracy margin")
    ax2.set_ylabel("honest ban rate (dashed)")
    ax.legend(fontsize=6)
    _save(fig, out, "fig_scale")


def fig_real_mnist(rows, out):
    fig, ax = plt.subplots(figsize=(COL_W, 1.8))
    series = {}
    for r in rows:
        key = (r["attack"], r["defense"])
        series.setdefault(key, {}).setdefault(int(r["round"]), []) \
            .append(float(r["accuracy"]))
    style = {("poison", "plain"): ("no layer", "0.6", "--"),
             ("poison", "dltf"): ("+DLTF", "0.1", "-"),
             ("none", "dltf"): ("clean", "0.4", ":")}
    for key, (lab, colour, ls) in style.items():
        if key not in series:
            continue
        rounds = sorted(series[key])
        ax.plot(rounds, [st.mean(series[key][r]) for r in rounds],
                label=lab, color=colour, linestyle=ls, linewidth=1.2)
    ax.set_xlabel("round")
    ax.set_ylabel("validation accuracy")
    ax.legend(fontsize=6, loc="lower right")
    _save(fig, out, "fig_real_mnist")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results")
    ap.add_argument("--out", default="figs")
    args = ap.parse_args()

    jobs = [("aggregator_grid.csv", fig_aggregator),
            ("m3_isolation.csv", fig_m3),
            ("scale.csv", fig_scale),
            ("real_mnist.csv", fig_real_mnist)]

    made = 0
    for fname, fn in jobs:
        path = os.path.join(args.results, fname)
        rows = _read(path)
        if not rows:
            print("skip %-22s (not found in %s)" % (fname, args.results))
            continue
        try:
            fn(rows, args.out)
            made += 1
        except Exception as exc:                       # noqa: BLE001
            print("FAILED on %s: %s: %s" % (fname, type(exc).__name__, exc))

    print("\n%d figure(s) written to %s/" % (made, args.out))
    if made:
        print("Copy the .pdf files into the paper's figs/ directory. The .tex")
        print("uses \\includegraphics without an extension, so a .pdf placed")
        print("there is picked up in preference to a .png automatically.")


if __name__ == "__main__":
    main()
