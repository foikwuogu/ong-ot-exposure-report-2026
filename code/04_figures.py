#!/usr/bin/env python3
"""Step 4 - figures, drawn only from report/stats.json and report/tables/*.csv.

  python code/04_figures.py            # DRAFT-stamped figures (default)
  python code/04_figures.py --final    # clean figures, only after the verification gate

Palette: validated categorical slots 1-2 (blue #2a78d6, orange #eb6834) and a four-step
single-hue ordinal blue ramp for severity; checked with the dataviz validator (all PASS).
"""
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIG = os.path.join(ROOT, "report", "figures")
TAB = os.path.join(ROOT, "report", "tables")
S = json.load(open(os.path.join(ROOT, "report", "stats.json"), encoding="utf-8"))
FINAL = "--final" in sys.argv
os.makedirs(FIG, exist_ok=True)

BLUE, ORANGE = "#2a78d6", "#eb6834"
RAMP = ["#86b6ef", "#5598e7", "#256abf", "#104281"]  # Low, Medium, High, Critical
INK, INK2, GRID, SURF = "#0b0b0b", "#52514e", "#e4e3df", "#fcfcfb"
Y = S["edition"]
SRC = f"Source: CISA ICS advisories via ONG-OT dataset v1.1 (doi:{S['input']['doi']}); KEV/EPSS/SSVC as of {S['input']['sources_pulled']}."

plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 9, "axes.edgecolor": GRID, "axes.labelcolor": INK2,
                     "xtick.color": INK2, "ytick.color": INK2, "axes.spines.top": False, "axes.spines.right": False,
                     "axes.grid": True, "grid.color": GRID, "grid.linewidth": 0.6, "axes.axisbelow": True,
                     "figure.facecolor": SURF, "axes.facecolor": SURF, "savefig.facecolor": SURF})


def finish(fig, name, title, note=SRC):
    # title and source note are anchored to the axes' full extent (tick labels, legend
    # included) so they can never collide with axis text
    fig.canvas.draw()
    r = fig.canvas.get_renderer()
    bb = fig.axes[0].get_tightbbox(r).transformed(fig.transFigure.inverted())
    fig.text(bb.x0, bb.y1 + 0.03, title, ha="left", va="bottom", fontsize=11, color=INK, fontweight="bold")
    fig.text(bb.x0, bb.y0 - 0.03, note, fontsize=7, color=INK2, ha="left", va="top")
    if not FINAL:
        fig.text(0.5, 0.5, "DRAFT", fontsize=70, color="#d0cfca", alpha=0.35, ha="center", va="center", rotation=25, zorder=100)
    fig.savefig(os.path.join(FIG, name), dpi=200, bbox_inches="tight")
    plt.close(fig)


def f1_advisories():
    t = pd.DataFrame(S["trend"])
    fig, ax = plt.subplots(figsize=(7.2, 3.4))
    x = range(len(t)); w = 0.4
    full = t.advisories_full_year.fillna(0)
    ax.bar([i - w / 2 for i in x], full, w, color=BLUE, edgecolor=SURF, linewidth=1, label="Full calendar year")
    ax.bar([i + w / 2 for i in x], t.advisories_ytd, w, color=ORANGE, edgecolor=SURF, linewidth=1, label=f"{S['ytd_label']} only")
    ax.set_xticks(list(x)); ax.set_xticklabels(t.year, rotation=0, fontsize=7.5)
    ax.set_ylabel("CISA advisories in ONG scope"); ax.grid(axis="x", visible=False)
    last = len(t) - 1
    ax.annotate(f"{int(t.advisories_ytd.iloc[-1])}", (last + w / 2, t.advisories_ytd.iloc[-1]), xytext=(0, 3),
                textcoords="offset points", ha="center", fontsize=8, color=INK)
    ax.annotate(f"{int(full.iloc[-2])}", (last - 1 - w / 2, full.iloc[-2]), xytext=(0, 3), textcoords="offset points", ha="center", fontsize=8, color=INK)
    ax.text(last - w / 2, 2, "n/a", ha="center", fontsize=6.5, color=INK2)
    ax.legend(frameon=False, loc="upper left")
    finish(fig, "fig1_advisories_by_year.png", f"Figure 1. ONG-relevant CISA ICS advisories per year, {t.year.min()}-{Y}")


def f2_cves():
    t = pd.DataFrame(S["trend"])
    fig, ax = plt.subplots(figsize=(7.2, 3.4))
    base = t.cves_ytd_excl_mega
    mega = t.cves_ytd - t.cves_ytd_excl_mega
    ax.bar(t.year, base, 0.7, color=BLUE, edgecolor=SURF, linewidth=1.2, label=f"CVEs in advisories with <= {S['config']['mega_threshold']} CVEs")
    ax.bar(t.year, mega, 0.7, bottom=base, color=ORANGE, edgecolor=SURF, linewidth=1.2, label=f"CVEs only in roll-up advisories (> {S['config']['mega_threshold']} CVEs)")
    ax.set_xticks(t.year); ax.set_xticklabels(t.year, fontsize=7.5); ax.grid(axis="x", visible=False)
    ax.set_ylabel(f"Unique CVEs, {S['ytd_label']}")
    ax.annotate(f"{int(t.cves_ytd.iloc[-1]):,} total\n{int(base.iloc[-1]):,} outside roll-ups", (t.year.iloc[-1], t.cves_ytd.iloc[-1]),
                xytext=(-8, -2), textcoords="offset points", ha="right", va="top", fontsize=7.5, color=INK)
    ax.legend(frameon=False, loc="upper left")
    finish(fig, "fig2_cves_by_year.png", f"Figure 2. Unique CVEs in ONG-relevant advisories, same {S['ytd_label']} window each year")


def f3_vendors():
    v = pd.DataFrame(S["vendors_ytd"]).iloc[::-1]
    fig, ax = plt.subplots(figsize=(7.2, 3.6))
    ax.barh(v.vendor, v.advisories, color=BLUE, edgecolor=SURF, height=0.65)
    for i, (a, c) in enumerate(zip(v.advisories, v.cves)):
        ax.text(a + 0.3, i, f"{a}  ({c} CVEs)", va="center", fontsize=7.5, color=INK2)
    ax.set_xlabel(f"Advisories, {Y} {S['ytd_label']}"); ax.grid(axis="y", visible=False)
    ax.set_xlim(0, v.advisories.max() * 1.35)
    vc = S["vendor_concentration"]
    finish(fig, "fig5_top_vendors.png", f"Figure 5. Top vendors by ONG-relevant advisories, {Y} (top five = {vc['top5_share_pct']}% of advisories)")


def f4_tiers():
    t = pd.read_csv(os.path.join(TAB, "t4_priority_tiers.csv"))
    labels = ["Tier 1\nIn CISA KEV", "Tier 2\nExploitation evidence\n(SSVC or EPSS top 5%)", "Tier 3\nCritical severity,\nno exploit evidence", "Tier 4\nAll other"]
    fig, ax = plt.subplots(figsize=(7.2, 3.4))
    x = range(4); w = 0.38
    b1 = ax.bar([i - w / 2 for i in x], t.ytd_prior_pct, w, color=ORANGE, edgecolor=SURF, label=f"{Y-1}, {S['ytd_label']}")
    b2 = ax.bar([i + w / 2 for i in x], t.ytd_current_pct, w, color=BLUE, edgecolor=SURF, label=f"{Y}, {S['ytd_label']}")
    for bars, n in [(b1, t.ytd_prior), (b2, t.ytd_current)]:
        for b, k in zip(bars, n):
            ax.text(b.get_x() + b.get_width() / 2, b.get_height() + 1, f"{k:,}", ha="center", fontsize=7.5, color=INK2)
    ax.set_xticks(list(x)); ax.set_xticklabels(labels, fontsize=7.5); ax.grid(axis="x", visible=False)
    ax.set_ylabel("% of unique CVEs in scope (count on bar)")
    ax.legend(frameon=False, loc="upper left")
    finish(fig, "fig4_priority_tiers.png", "Figure 4. Exploitation-first priority tiers for ONG-relevant CVEs")


def f5_cwes():
    c = pd.DataFrame(S["cwes_ytd"]).iloc[::-1]
    fig, ax = plt.subplots(figsize=(7.2, 3.8))
    lab = [f"{a}  {b}" for a, b in zip(c.cwe, c.name)]
    for i, (h, n) in enumerate(zip(c.share_pct_2012_2025, c.share_pct)):
        ax.plot([h, n], [i, i], color=GRID, linewidth=2, zorder=1)
    ax.scatter(c.share_pct_2012_2025, range(len(c)), s=40, color=ORANGE, edgecolor=SURF, linewidth=1.5, zorder=2, label=f"{S['trend'][0]['year']}-{Y-1} (all ONG advisories)")
    ax.scatter(c.share_pct, range(len(c)), s=40, color=BLUE, edgecolor=SURF, linewidth=1.5, zorder=3, label=f"{Y}, {S['ytd_label']}")
    ax.set_yticks(range(len(c))); ax.set_yticklabels(lab, fontsize=7.5); ax.grid(axis="y", visible=False)
    ax.set_xlabel("% of ONG-relevant advisories citing the weakness")
    ax.legend(frameon=False, loc="upper center", bbox_to_anchor=(0.4, -0.13), ncol=2, fontsize=7.5)
    finish(fig, "fig6_top_cwes.png", f"Figure 6. The ten most-cited weaknesses (CWE) in {Y}, against their historical share")


def f6_severity():
    t = pd.DataFrame(S["trend"])
    t = t[t.year >= 2016]
    fig, ax = plt.subplots(figsize=(7.2, 3.3))
    bottom = pd.Series([0.0] * len(t), index=t.index)
    for col, lab, colr in [("low_pct", "Low", RAMP[0]), ("medium_pct", "Medium", RAMP[1]), ("high_pct", "High", RAMP[2]), ("critical_pct", "Critical", RAMP[3])]:
        v = t[col].fillna(0)
        ax.bar(t.year, v, 0.7, bottom=bottom, color=colr, edgecolor=SURF, linewidth=1.2, label=lab)
        bottom += v
    for yr, cp in zip(t.year, t.critical_pct):
        ax.text(yr, 101, f"{cp:.0f}%", ha="center", fontsize=7, color=INK2)
    ax.set_ylim(0, 108); ax.set_xticks(t.year); ax.grid(axis="x", visible=False)
    ax.set_ylabel("% of advisories (label = Critical share)")
    ax.legend(frameon=False, ncol=4, loc="upper center", bbox_to_anchor=(0.5, -0.1), fontsize=7.5)
    finish(fig, "fig3_severity_mix.png", f"Figure 3. CISA severity mix of ONG-relevant advisories, 2016-{Y} ({Y}: {S['ytd_label']})")


if __name__ == "__main__":
    for f in [f1_advisories, f2_cves, f3_vendors, f4_tiers, f5_cwes, f6_severity]:
        f()
    print("figures written to", FIG, "(FINAL)" if FINAL else "(DRAFT-stamped)")
