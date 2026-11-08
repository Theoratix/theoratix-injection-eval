"""Run the study.

  python -m injeval.run --provider anthropic --model <model-id> --out results/<name>.jsonl

Resumable: episodes already in --out are skipped, so you can stop and restart.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

from .agent import run_episode
from .defenses import DEFAULT_DEFENSES, parse_defense
from .providers import make_provider
from .tasks import STYLES, build_tasks


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--provider", required=True, choices=["anthropic", "openai", "openai_compat", "mock"])
    p.add_argument("--model", required=True, help="model id, recorded in results")
    p.add_argument("--base-url", help="for openai_compat (vLLM, Ollama, ...)")
    p.add_argument("--api-key-env", help="env var holding the API key")
    p.add_argument("--monitor-provider", help="defaults to --provider")
    p.add_argument("--monitor-model", help="defaults to --model")
    p.add_argument("--monitor-base-url")
    p.add_argument("--defenses", default=",".join(DEFAULT_DEFENSES))
    p.add_argument("--styles", default=",".join(STYLES))
    p.add_argument("--scenarios", help="comma list of scenario ids, e.g. a01,e05")
    p.add_argument("--limit", type=int, help="keep only the first N scenarios (pilot runs)")
    p.add_argument("--repeats", type=int, default=1)
    p.add_argument("--temperature", type=float)
    p.add_argument("--max-steps", type=int, default=8)
    p.add_argument("--workers", type=int, default=4)
    p.add_argument("--seed", type=int, default=0)
    p.add_argument("--out", required=True)
    p.add_argument("--dry-run", action="store_true", help="print the episode count and exit")
    a = p.parse_args(argv)

    defenses = [parse_defense(d) for d in a.defenses.split(",") if d.strip()]
    styles = set(a.styles.split(","))
    tasks = [t for t in build_tasks() if t.style in styles]
    if a.scenarios:
        keep = set(a.scenarios.split(","))
        tasks = [t for t in tasks if t.scenario.sid in keep]
    if a.limit:
        sids = sorted({t.scenario.sid for t in tasks}, key=lambda s: (s[0] != "a", int(s[1:])))
        # balance answer/email tasks in pilots
        a_ids = [s for s in sids if s.startswith("a")][: (a.limit + 1) // 2]
        e_ids = [s for s in sids if s.startswith("e")][: a.limit // 2]
        keep = set(a_ids + e_ids)
        tasks = [t for t in tasks if t.scenario.sid in keep]

    jobs = [(t, d, r) for r in range(a.repeats) for d in defenses for t in tasks]
    os.makedirs(os.path.dirname(os.path.abspath(a.out)), exist_ok=True)
    done = set()
    if os.path.exists(a.out):
        with open(a.out) as f:
            for line in f:
                try:
                    r = json.loads(line)
                    if not r.get("error"):
                        done.add((r["task_id"], r["defense"], r["repeat"]))
                except (json.JSONDecodeError, KeyError):
                    pass
    jobs = [j for j in jobs if (j[0].task_id, j[1].name, j[2]) not in done]
    print(f"{len(jobs)} episodes to run ({len(done)} already done) | {len(tasks)} tasks x "
          f"{len(defenses)} defenses x {a.repeats} repeats", file=sys.stderr)
    if a.dry_run or not jobs:
        return

    agent = make_provider(a.provider, a.model, a.temperature, a.base_url, a.api_key_env, a.seed)
    mon_kind = a.monitor_provider or a.provider
    mon_model = a.monitor_model or a.model
    monitor = make_provider(mon_kind, mon_model, 0.0 if mon_kind != "mock" else None,
                            a.monitor_base_url or (a.base_url if mon_kind == a.provider else None),
                            a.api_key_env if mon_kind == a.provider else None, a.seed)

    lock = threading.Lock()
    n_ok = n_err = 0

    def work(job):
        t, d, r = job
        rec = run_episode(t, d, agent, monitor, a.max_steps)
        rec.update(model=a.model, provider=a.provider, monitor_model=mon_model if d.monitor else None,
                   repeat=r, temperature=a.temperature)
        return rec

    with open(a.out, "a") as f, ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = [ex.submit(work, j) for j in jobs]
        for i, fut in enumerate(as_completed(futs), 1):
            rec = fut.result()
            with lock:
                f.write(json.dumps(rec) + "\n")
                f.flush()
                if rec["error"]:
                    n_err += 1
                else:
                    n_ok += 1
            if i % 25 == 0 or i == len(futs):
                print(f"  {i}/{len(futs)} done ({n_err} errors)", file=sys.stderr)
    if n_err:
        print(f"{n_err} episodes errored; rerun the same command to retry them.", file=sys.stderr)


if __name__ == "__main__":
    main()
