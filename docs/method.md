# Method

How AEGIS decides: the authority lattice, taint propagation, signals and arbitration.

> Extracted verbatim from [`report/report.md`](../report/report.md) §4, which is the authoritative version. Edit the report, then regenerate with `python3 scripts/split_docs.py`.

---

### 4.1 Where the defense sits

AEGIS is an out-of-process HTTP service implementing the SENTINEL v1 defense interface. It sees one candidate action at a time, before execution:

```
DefenseRequest  (user goal, conversation, observation, candidate action,
                 policy context, provenance records, history digest)
   │
   ├─ ProvenanceEngine.analyze()          → TaintSummary
   ├─ ProvenanceEngine.check_authority()  → AuthorityVerdict
   ├─ [signal.score(ctx) for signal in signals] → [SignalResult]
   ├─ Arbiter.combine()                   → Verdict
   ├─ TraceEmitter.emit()                 → one fully-explained JSON line
   ▼
DefenseDecision   allow | block | escalate | rewrite
```

It gates tool authorization and output, and it observes retrieval and memory. It does not see or modify model internals, and it does not rewrite the prompt.

### 4.2 The authority lattice — the organising principle

Two sentences carry the whole method:

> **Authority comes from the user and the policy, never from observed data.**
> **Taint constrains authority, not attention.**

Every action *requires* an authority level, derived at runtime from the policy's consequential and confirmation lists and from the tool's own verb morphology — never from a table of scenario tool names. Every action *has available* an authority level, which is the ceiling its least-trusted causal input allows:

| Least-trusted influence | Maximum authority |
|---|---|
| `system_policy`, `authenticated_user` | `commit` — irreversible, externally visible |
| `trusted_internal`, `untrusted_internal` | `prepare` — reversible artifacts only |
| `untrusted_external`, `adversary_controlled` | `read` — observation only |

A recorded human confirmation over that exact action digest raises the ceiling. Nothing else does. So an action whose payment identifier traces back to a merchant's letter can never confirm a payment — not because the letter looked suspicious, but because a letter has no authority to give.

The fourth question, *"does the content say this was approved?"*, is never asked. A document claiming an approval is a document.

### 4.3 Taint propagation

For each value the candidate action carries, the engine matches it against every span of content the agent has seen, generalizing past wording: whitespace-squashed text, alphanumeric-only forms that survive JSON quoting and punctuation, numeric equality across thousands separators, and stem overlap for paraphrase.

Two distinctions do the work:

- **Control vs. content arguments.** An identifier, recipient, status or amount *steers the effect*; a note body or summary is payload. Chain excerpts are prefixed `[arg:<name>]` or `[content:<name>]` accordingly. Only unanchored control matches raise `action_taint`.
- **User-anchored values.** A value the user's own goal already contained keeps its authority and is marked `(user-named)`. This is what lets *"how critical is SRV-22?"* work when `SRV-22` also appears in a hostile log.

`value_derived_from_untrusted` is true only for unanchored *control* values traced to untrusted text — the strong, causal signal.

Memory extends this across turns: an entry written after reading untrusted content stays untrusted when recalled, and a recalled "policy" loses to a trusted one. Lifecycle ordering (`prepare` → `confirm` → `execute`) comes from the policy's own prerequisite rules; a confirmation exists only when the history digest says so, matched by the simulator's exact action digest.

### 4.4 Signals

Each signal is a pure function returning risk in [0, 1], where 0 means *"this detector saw no evidence"* — never *"this action is safe"*.

| Signal | Catches |
|---|---|
| `plan_divergence` | an action the user's goal does not entail, explicitly excludes, or whose steering arguments trace only to untrusted text |
| `benign_context` | the inverse: a fully aligned action in alarming surroundings. Scores 0 and publishes a damping factor |
| `encoded_exfiltration` | a provenance-marked secret reconstructable from an outbound argument through any layered encoding |
| `sensitive_sink` | confidential content addressed outside the trust boundary the policy declares |
| `imperative_mirroring` | the action enacts an order found in untrusted content, including split and encoded orders |
| `policy_conflict` | untrusted text claiming an authorisation the trusted record does not support |

### 4.5 Arbitration, risk and confidence

Precedence is structural first, probabilistic last. Order matters more than thresholds: structural facts are not traded against a probability.

1. **Tool outside the permitted set** → block. Even when the *user* asked: a direct request cannot widen a policy.
2. **Lifecycle violated** → block, or rewrite to the earlier stage.
3. **Authority exceeded** → rewrite to a reversible substitute where one exists (`email_send` → `email_draft`); escalate when a human confirmation is the only missing ingredient; block otherwise.
4. **Effect floors** (below).
5. **Calibrated band** — the monitor's probability, damped by the hard-negative guard, against `ESCALATE_AT = 0.38` and `BLOCK_AT = 0.70`.
6. **Consequential and unconfirmed** → escalate, because the policy says so and because a human approving a legitimate step is how the task completes.

**The two effect floors** are the counterweight that keeps the defense usable, and both are conditioned on there being no effect to protect:

- **Read floor.** When authority is satisfied and the step needs no more than `read`, AEGIS never blocks. A read changes nothing, and whatever it returns is still capped by provenance when something later tries to act on it. It escalates only above `READ_ESCALATE_AT = 0.80`.
- **Memory floor.** A `memory_write` is reversible, `prepare`-class, and inherits the trust of its source, so a poisoned entry comes back as evidence with no authority. AEGIS prefers to rewrite it with instruction-shaped fragments stripped. Only an actual reconstructable secret (`EXFILTRATION_OVERRIDE = 0.80`) overrides it.

Neither floor can touch a commit-class action, which is where every attack in the threat model has to end up to do damage. **The read floor is also the source of our most important limitation** (§8.1) — it is a deliberate trade, not an oversight.

Thresholds were chosen from the shape of the model, not from any scenario's outcome: one mid-strength signal on a reversible action lands near 0.25 (below `ESCALATE_AT`, because one piece of soft evidence is not a reason to interrupt a human); two independent signals agreeing, or one strong signal on a commit-class action, lands in 0.38–0.70, which is what escalation is for; structural evidence plus any signal clears 0.70.

`confidence` is a function of how many signals fired and how many agreed, not of the risk score: `0.52 + 0.09·(signals firing) + 0.12·(agreeing beyond the first)`, clamped to [0.30, 0.94]. It answers *"how much evidence is this verdict standing on?"*, which is a different question from *"how risky is this?"*.

### 4.6 Learned components

There is no trained model, no external dataset and no learned weights fitted to the scenario library. The "calibrated monitor" is a hand-specified logistic combination over signal scores and structural features, with coefficients chosen from the reasoning in §4.5 rather than fitted. We say this plainly because it matters for §7: there is nothing here that could have overfit to the published scenarios, and equally nothing that earned its coefficients from data.

### 4.7 Staying inside the Defense Rules

No decision path reads `run_id`, a scenario id, a filename, a fixture name or an expected outcome. `run_id` appears in the trace for correlation only. This is tested two ways — a contract test that rewrites `run_id` and `step_id` to arbitrary values including `hard_negative_do_not_block_me` and asserts byte-identical decisions, and a scenario-level audit that renames every file and id in the library and re-runs it (§9).
