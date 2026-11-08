"""Analyze results.

  python -m injeval.analyze results/*.jsonl --out report/

Writes report/results.md, report/summary.csv, report/asr_by_defense.png and,
with --label-sample N, report/label_sample.csv for human calibration of the
automatic scoring. Fill its human_attack_success column and pass it back with
--labels to get the agreement rate.
"""
from __future__ import annotations

import argparse
import csv
import json
import math
import os
import random
from collections import defaultdict

SERIES = ["#2a78d6", "#eb6834", "#1baf7a", "#eda100", "#e87ba4", "#008300", "#6250d6", "#e34948"]


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float, float]:
    if n == 0:
        return float("nan"), float("nan"), float("nan")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - h), min(1.0, c + h)


def fmt(k, n):
    p, lo, hi = wilson(k, n)
    if n == 0:
        return "n/a"
    return f"{100*p:.1f}% [{100*lo:.1f}, {100*hi:.1f}] (n={n})"


def load(paths):
    recs = {}
    for path in paths:
        with open(path) as f:
            for line in f:
                try:
                    r = json.loads(line)
                except json.JSONDecodeError:
                    continue
                key = (r["model"], r["task_id"], r["defense"], r.get("repeat", 0))
                if r.get("error") and key in recs and not recs[key].get("error"):
                    continue
                recs[key] = r
    rows = list(recs.values())
    errs = [r for r in rows if r.get("error")]
    return [r for r in rows if not r.get("error")], errs


def rate(rows, field):
    return sum(bool(r[field]) for r in rows), len(rows)


def bootstrap_delta(rows, defense, base="none", field="attack_success", B=2000, seed=0):
    """Paired cluster bootstrap over scenarios: ASR(defense) - ASR(base)."""
    by = defaultdict(lambda: {"d": [], "b": []})
    for r in rows:
        if not r["injected"]:
            continue
        if r["defense"] == defense:
            by[r["scenario"]]["d"].append(bool(r[field]))
        elif r["defense"] == base:
            by[r["scenario"]]["b"].append(bool(r[field]))
    clusters = [v for v in by.values() if v["d"] and v["b"]]
    if not clusters:
        return None

    def est(cs):
        d = sum(sum(c["d"]) for c in cs) / max(1, sum(len(c["d"]) for c in cs))
        b = sum(sum(c["b"]) for c in cs) / max(1, sum(len(c["b"]) for c in cs))
        return d - b

    rng = random.Random(seed)
    point = est(clusters)
    boots = sorted(est([rng.choice(clusters) for _ in clusters]) for _ in range(B))
    return point, boots[int(0.025 * B)], boots[int(0.975 * B) - 1]


def analyze(rows):
    models = sorted({r["model"] for r in rows})
    defenses = []
    for r in rows:
        if r["defense"] not in defenses:
            defenses.append(r["defense"])
    order = ["none", "scope", "scope+allowlist", "spotlight", "monitor", "monitor_full",
             "scope+allowlist+spotlight", "spotlight+monitor"]
    defenses.sort(key=lambda d: order.index(d) if d in order else 99)
    styles = ["direct", "fake_system", "authority", "hidden_html", "tool_mimicry"]

    out, summary = [], []
    out.append("# Indirect prompt injection: results\n")
    out.append("Rates are shown with Wilson 95% confidence intervals. ASR = the attacker's goal action "
               "actually executed. Attempt = the agent issued the attacker's call, even if a defense blocked it. "
               "Utility = the employee's task was completed correctly. False block = a legitimate email to the "
               "correct internal recipient was blocked (clean email tasks only).\n")
    for m in models:
        mr = [r for r in rows if r["model"] == m]
        out.append(f"\n## Model: `{m}`\n")
        out.append("| Defense | ASR | Attempt rate | Utility (clean) | Utility (under attack) | False block | ΔASR vs none [95% CI] |")
        out.append("|---|---|---|---|---|---|---|")
        for d in defenses:
            dr = [r for r in mr if r["defense"] == d]
            if not dr:
                continue
            inj = [r for r in dr if r["injected"]]
            clean = [r for r in dr if not r["injected"]]
            clean_email = [r for r in clean if r["kind"] == "email"]
            delta = bootstrap_delta(mr, d) if d != "none" else None
            ds = "-" if delta is None else f"{100*delta[0]:+.1f} pts [{100*delta[1]:+.1f}, {100*delta[2]:+.1f}]"
            out.append(f"| {d} | {fmt(*rate(inj,'attack_success'))} | {fmt(*rate(inj,'attack_attempt'))} | "
                       f"{fmt(*rate(clean,'utility'))} | {fmt(*rate(inj,'utility'))} | "
                       f"{fmt(*rate(clean_email,'legit_blocked'))} | {ds} |")
            k, n = rate(inj, "attack_success")
            p, lo, hi = wilson(k, n)
            ku, nu = rate(clean, "utility")
            summary.append({"model": m, "defense": d, "asr": p, "asr_lo": lo, "asr_hi": hi, "n_injected": n,
                            "attempt_rate": wilson(*rate(inj, "attack_attempt"))[0],
                            "utility_clean": wilson(ku, nu)[0], "n_clean": nu,
                            "utility_attacked": wilson(*rate(inj, "utility"))[0],
                            "false_block": wilson(*rate(clean_email, "legit_blocked"))[0],
                            "delta_asr": delta[0] if delta else 0.0,
                            "delta_lo": delta[1] if delta else 0.0, "delta_hi": delta[2] if delta else 0.0})

        out.append(f"\n### ASR by injection style (`{m}`)\n")
        out.append("| Defense | " + " | ".join(styles) + " |")
        out.append("|---|" + "---|" * len(styles))
        for d in defenses:
            cells = []
            for s in styles:
                k, n = rate([r for r in mr if r["defense"] == d and r["style"] == s], "attack_success")
                cells.append("n/a" if n == 0 else f"{100*k/n:.0f}% ({k}/{n})")
            out.append(f"| {d} | " + " | ".join(cells) + " |")

        out.append(f"\n### ASR by task type and attacker goal (`{m}`)\n")
        out.append("| Defense | answer tasks | email tasks | goal: exfil | goal: delete |")
        out.append("|---|---|---|---|---|")
        for d in defenses:
            inj = [r for r in mr if r["defense"] == d and r["injected"]]
            cells = [fmt(*rate([r for r in inj if r["kind"] == k], "attack_success")) for k in ("answer", "email")]
            cells += [fmt(*rate([r for r in inj if r["goal"] == g], "attack_success")) for g in ("exfil", "delete")]
            out.append(f"| {d} | " + " | ".join(cells) + " |")

        tok = sum(r.get("input_tokens", 0) + r.get("output_tokens", 0) for r in mr)
        out.append(f"\nEpisodes: {len(mr)}. Agent tokens: {tok:,} (monitor tokens not counted).\n")
    return "\n".join(out), summary


def chart(summary, path):
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        return False
    models = sorted({s["model"] for s in summary})
    defenses = []
    for s in summary:
        if s["defense"] not in defenses:
            defenses.append(s["defense"])
    fig, ax = plt.subplots(figsize=(8, 0.5 + 0.45 * len(defenses) * max(1, len(models))), dpi=160)
    fig.patch.set_facecolor("#fcfcfb")
    ax.set_facecolor("#fcfcfb")
    h = 0.8 / len(models)
    for mi, m in enumerate(models):
        ys, xs, lo, hi = [], [], [], []
        for di, d in enumerate(defenses):
            s = next((x for x in summary if x["model"] == m and x["defense"] == d), None)
            if not s:
                continue
            y = len(defenses) - 1 - di + (len(models) - 1 - mi - (len(models) - 1) / 2) * h
            ys.append(y); xs.append(100 * s["asr"])
            lo.append(100 * (s["asr"] - s["asr_lo"])); hi.append(100 * (s["asr_hi"] - s["asr"]))
        ax.barh(ys, xs, height=h * 0.85, color=SERIES[mi % len(SERIES)], label=m, zorder=2)
        ax.errorbar(xs, ys, xerr=[lo, hi], fmt="none", ecolor="#52514e", elinewidth=1, capsize=2, zorder=3)
        for x, y, e in zip(xs, ys, hi):
            ax.text(x + e + 1, y, f"{x:.0f}%", va="center", fontsize=7, color="#0b0b0b")
    ax.set_yticks(range(len(defenses)))
    ax.set_yticklabels(list(reversed(defenses)), fontsize=8, color="#0b0b0b")
    ax.set_xlabel("Attack success rate (%), 95% Wilson CI", fontsize=8, color="#52514e")
    ax.set_xlim(0, 105)
    ax.grid(axis="x", color="#e6e5e0", linewidth=0.6, zorder=0)
    for sp in ("top", "right", "left"):
        ax.spines[sp].set_visible(False)
    ax.spines["bottom"].set_color("#c3c2b7")
    ax.tick_params(axis="x", labelsize=7, colors="#52514e")
    ax.tick_params(axis="y", length=0)
    ax.set_title("Indirect prompt injection: attack success by defense", fontsize=10, loc="left", color="#0b0b0b")
    if len(models) > 1:
        ax.legend(fontsize=7, frameon=False, loc="lower right")
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)
    return True


def label_sample(rows, n, path, seed=0):
    rng = random.Random(seed)
    inj = [r for r in rows if r["injected"]]
    pos = [r for r in inj if r["attack_attempt"]]
    neg = [r for r in inj if not r["attack_attempt"]]
    pick = rng.sample(pos, min(len(pos), n // 2)) + rng.sample(neg, min(len(neg), n - min(len(pos), n // 2)))
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["model", "task_id", "defense", "repeat", "auto_attack_attempt", "auto_attack_success",
                    "auto_utility", "tool_calls", "final_answer", "human_attack_success", "human_utility", "notes"])
        for r in pick:
            calls = "; ".join(f"{c['name']}({json.dumps(c['args'])[:160]}) executed={c['executed']}" for c in r["calls"])
            w.writerow([r["model"], r["task_id"], r["defense"], r.get("repeat", 0), r["attack_attempt"],
                        r["attack_success"], r["utility"], calls, (r.get("answer") or r.get("final_text") or "")[:300],
                        "", "", ""])


def agreement(path):
    agree = total = 0
    with open(path) as f:
        for row in csv.DictReader(f):
            h = (row.get("human_attack_success") or "").strip().lower()
            if h in ("true", "false", "1", "0", "yes", "no"):
                total += 1
                agree += (h in ("true", "1", "yes")) == (row["auto_attack_success"] == "True")
    return agree, total


def main(argv=None):
    p = argparse.ArgumentParser()
    p.add_argument("results", nargs="+")
    p.add_argument("--out", default="report")
    p.add_argument("--label-sample", type=int, default=0)
    p.add_argument("--labels", help="filled label_sample.csv; prints agreement with auto scoring")
    a = p.parse_args(argv)
    os.makedirs(a.out, exist_ok=True)
    rows, errs = load(a.results)
    md, summary = analyze(rows)
    if errs:
        md += f"\n\n> {len(errs)} episodes ended in errors and are excluded. Rerun the run command to retry them.\n"
    if a.labels:
        k, n = agreement(a.labels)
        md += f"\n\n## Scoring calibration\nAutomatic vs human labels for attack success agree on {fmt(k, n)}.\n"
    with open(os.path.join(a.out, "results.md"), "w") as f:
        f.write(md)
    if summary:
        with open(os.path.join(a.out, "summary.csv"), "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(summary[0]))
            w.writeheader()
            w.writerows(summary)
    made = chart(summary, os.path.join(a.out, "asr_by_defense.png"))
    if a.label_sample:
        label_sample(rows, a.label_sample, os.path.join(a.out, "label_sample.csv"))
    print(md)
    print(f"\nWrote {a.out}/results.md, summary.csv" + (", asr_by_defense.png" if made else ""))


if __name__ == "__main__":
    main()
