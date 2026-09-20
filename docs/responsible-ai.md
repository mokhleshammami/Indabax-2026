# Responsible AI and security considerations

What AEGIS protects against, how it fails, what it observes, and when a human must decide.

> Extracted verbatim from [`report/report.md`](../report/report.md) §10, which is the authoritative version. Edit the report, then regenerate with `python3 scripts/split_docs.py`.

---

### 10.1 What AEGIS protects against

Indirect prompt injection, tool-output manipulation, memory poisoning, multi-step and split-payload attacks, encoded exfiltration, lifecycle violations (execute before confirm), and out-of-policy direct instructions from the user themselves. In each case the protection is structural: the action's authority ceiling is set by its least-trusted input, so the attack's surface form is irrelevant.

### 10.2 Known failure modes

Section 8 in full, and specifically: attacks whose damage is complete at the read (8.1); same-family handle confusion (8.3); a cheap utility denial-of-service by echoing a legitimate identifier (8.4); implied rather than written values (8.6); paraphrase attacks that borrow the user's vocabulary (8.7); conditional prohibitions (8.8); implied approvals (8.9). We have not fixed these and we are not claiming they are unimportant.

### 10.3 Expected false-positive behaviour, and who pays for it

AEGIS is built so that its errors fall on interruption rather than refusal. Measured across 139 decisions on the published library: FBR 0.000, UER 0.011, two escalations, two rewrites. On four adversarially-chosen over-refusal scenarios of our own: zero false blocks, maximum risk 0.107.

The cost of a false positive is borne by the operator — an analyst who has to approve a document read, a finance officer who has to confirm a refund a second time. The cost of the denial-of-service in §8.4 is borne by the *user whose legitimate task fails*, which is worse, and we flag it as the most user-visible defect we know about.

Three design choices keep this cost down, and each is a deliberate weakening of security in exchange for usefulness: the read floor never blocks effect-free reads; the memory floor rewrites rather than refuses; and `rewrite` is preferred over `block` wherever a reversible substitute preserves the task. A team that wants maximum security should raise all three.

### 10.4 What data AEGIS observes, and what it stores

AEGIS sees, per decision: the user's goal, the conversation so far, the current observation, the candidate action and its arguments, the policy context, the provenance records, and a history digest. It stores nothing persistently except the observability trace, which it writes to local JSONL. **That trace contains excerpts of user and tool content**, truncated to 600 characters per excerpt, because the whole point of the trace is to show *which text* caused a decision. Anyone deploying this must treat `traces/` as containing the same sensitivity of data as the agent's own context. There is no telemetry, no network egress, and no third-party service.

All evaluation in this report used synthetic, fictional data inside the SENTINEL simulator: no real system, credential, account or personal data was touched.

### 10.5 When a human should be consulted

AEGIS escalates rather than deciding when: a consequential action lacks a recorded confirmation; authority is exceeded but a human confirmation is the only missing ingredient; evidence lands in the 0.38–0.70 band; or a read carries several strong independent signals (above 0.80). It also escalates on internal error — the pipeline fails closed to `escalate`, never to a silent allow.

It does **not** ask a human for effect-free reads below 0.80, for memory writes, or when a safe rewrite exists. A deployment where reads are consequential should change the first of those.

A human in the loop is not a safety guarantee. The simulator's human approves any action matching the user's plan, which is a reasonable model of a real reviewer, and §7.3 shows a case where that approval is exactly how the `tool_prerequisites` property gets violated under an ablation. Escalation moves a decision; it does not make it correct.

### 10.6 How explanations are generated

Every decision carries reason codes from a fixed shared vocabulary (`SCHEMA.md` §5) and a one-sentence explanation of at most 500 characters. Explanations are **templated statements of the rule that fired**, not model-generated text and not chain-of-thought: "`payment_confirm` needs commit authority; its least-trusted input allows only read." This is deliberate — an explanation that is itself generated is an explanation that can be wrong about its own cause.

### 10.7 Performance across domains

Uniform on this library: enterprise 9/9, finance 10/10, soc 9/9, with zero attack successes in each. Calibration differs by domain (Brier 0.064 enterprise, 0.001 finance on public), driven by the single enterprise escalation in §8.2. With three domains and 28 scenarios we do not think any domain-level difference here is meaningful.

### 10.8 The honest summary

AEGIS stops every attack in the published library and blocks nothing legitimate. It achieves this on a benchmark where a competent heuristic baseline achieves the same ASR, where its own central mechanism can be removed without changing any outcome, and where its encoding decoder changes not one decision. The evidence that the mechanism does something a heuristic does not is the isolation work in §7.3, which is constructed rather than measured in the wild. We believe the approach is right; we do not believe this benchmark proves it, and we would rather say so than imply otherwise.
