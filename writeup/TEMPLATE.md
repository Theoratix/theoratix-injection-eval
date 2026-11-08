# Least privilege beats persuasion: an empirical study of indirect prompt injection in tool-using agents

*Mohammad Imtiaz, Theoratix.ai, November 2026*

> Fill every `[ ]` from `report/results.md`. Keep a finding only if its confidence interval supports it.
> Change the title once you know what the data says.

## Abstract (≈150 words)

Tool-using LLM agents read untrusted content while holding the ability to act. We measure how often agents built on [N] models act on instructions hidden in retrieved documents, across 40 enterprise tasks, 5 injection styles and 8 defense configurations ([total] episodes).

Without defenses, the attacker's action executed in [x]% of injected tasks (95% CI [ , ]). Least-privilege tool exposure with argument constraints cut this to [y]%, at a utility cost of [z] points. Spotlighting reduced attempts by [ ] points. A trusted monitor that sees only the user's request blocked [ ]% of attacks at a [ ]% false-block rate. Giving the monitor the retrieved document [increased / did not change] its failure rate.

[One sentence on the main takeaway.]

## 1. Why this matters

- Agents now read email, documents and web pages and can send, buy and delete. Any text they read is a potential instruction channel.
- Model-level robustness and system-level containment are different properties. This study measures both, separately: attempt rate vs success rate.

## 2. Setup

- **Environment:** sandboxed tools (read, list, email, delete, submit). Scoring is deterministic from the tool-call log.
- **Tasks:** 20 answer tasks and 20 email tasks. Each has a clean control and 5 injection styles. Attacker goals (exfil / delete) and placement (mid / end) are balanced.
- **Defenses:** see the README table.
- **Models:** [list model ids, dates run, temperature, repeats].
- **Monitor model:** [id].
- **Statistics:** Wilson 95% CIs; paired cluster bootstrap over scenarios for ΔASR.
- **Scoring check:** on [n] hand-labeled episodes, the automatic scores agreed with human labels [ ]% of the time.

## 3. Results

### 3.1 Susceptibility without defenses (RQ1)
[Table: ASR and attempt rate per model at `none`.]
[Table: ASR by injection style. Which style was most effective? Did `tool_mimicry` or `fake_system` outperform plain overrides?]

### 3.2 Structural defenses (RQ2)
[Compare `scope` with `scope+allowlist`. Key point to test: `scope` alone leaves email tasks exposed, because `send_email` is needed. Argument constraints close that gap.]
[Utility cost.]

### 3.3 Spotlighting (RQ3)
[Change in attempt rate, not just ASR. Does it hold across models?]

### 3.4 Trusted monitoring (RQ4)
[`monitor` vs `monitor_full`: ASR, false-block rate, utility under attack. Is the monitor itself injectable when it sees the content?]

![ASR by defense](../report/asr_by_defense.png)

## 4. What I'd tell a team shipping agents

1. [Finding → design rule]
2. [ ]
3. [ ]

## 5. Limitations

Synthetic documents; non-adaptive attacker; short single-document tasks; rule-based scoring (calibrated on [n] labels); [ ] models only.

## 6. Next steps

- Adaptive attacks: optimize injections against each defense.
- Multi-step workflows with several untrusted sources.
- Capability-based designs (CaMeL-style) as a comparison point.
- Monitor scaling: does a weaker monitor suffice when it cannot see the untrusted content?

## Reproducibility

Code, task set and raw episode logs: [GitHub link]. Commands: see README.
