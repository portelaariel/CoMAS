# CoMAS LLM Auditor

This package audits completed CoMAS experiments without entering the runtime
decision or mitigation path. It reads `metadata.json`, `summary.json`, and
`timeline.ndjson`; it never publishes to ETCD, elects an executor, calls
FlowBlocker, or installs OpenFlow rules.

The deterministic mode provides reference verdicts conditional on the recorded
facts and the documented rules:

```bash
python3 -m llm_auditor experiments/results/<run> --mode audit
```

## Evidence-based deterministic verifier (rules 2.1)

`rules.py` is a pure verifier; `runtime_evidence.py` adapts immutable runtime
events without importing the controller. The five dimensions are independent:

- Protocol consistency checks quorum, model identity, recorded authorization,
  claim ownership and the applicable state/execution predicates. A known
  violation dominates missing evidence; otherwise a required unknown produces
  `INSUFFICIENT_EVIDENCE`. `CONSISTENT` is not a complete formal proof of the
  protocol: optional freshness/topology validity fields are checked when
  present, and their absence does not establish those properties.
- Scenario correctness compares the episode's decision with the labelled
  laboratory scenario/policy, not the run-level TP/TN classification. Missing,
  invalid or contaminated ground truth and intermediate agent decisions remain
  `UNKNOWN`, even if the MCDA baseline has already reached `MITIGATE`.
- Decision stage describes the reported state. An invalid `AGREED` is still
  `FINAL`; stage is not evidence that quorum or authorization was valid.
- Execution status prioritizes recorded actuation over intended mode. A dry-run
  winner with intent and explicit non-actuation is `DRY_RUN_SUPPRESSED`; an
  authorized non-winner with a known coordinator is
  `SKIPPED_OTHER_COORDINATOR`. A recorded attempt with no recorded outcome is
  `UNKNOWN`, not `FAILED`. A live winner stopped by a kill-switch is not
  automatically classified as a failed attempt.
- Operational effectiveness requires an observed outcome after execution.
  Successful execution/installation alone is insufficient. Failed actuation is
  `INEFFECTIVE`; no applicable local actuation is `NOT_APPLICABLE`. A run-level
  disruption flag cannot attribute effectiveness to multiple separate episodes.

Votes are checked per event, never pooled across windows. Explicit vote lists
and model identities are also compared with responsible-domain proposals when
those proposals are supplied. Repeated winner events do not imply multiple
owners. Different owners may legitimately succeed each other after claim lease
expiry; multiple runtime owners with unknown intervals cannot prove overlap.
Synthetic fixtures with a declared single-episode ownership invariant are
checked within that explicitly supplied scope.

Missing/null execution fields remain unknown instead of becoming zero. Counts
of positive observations with incomplete coverage are lower bounds, not proof
of complete logging. Non-mitigation states describe that no actuation was
requested; absent records still do not independently verify data-plane behavior.
Malformed JSON and conflicting duplicate event payloads are rejected rather
than silently discarded. An absent attack-start boundary leaves DDoS episode
ground truth unknown because benign priming windows may be present.

Rules 2.1 correct the interpretation of legacy MCDA simulations. That layer's
`Mitigator` sets `attempted=true` before returning early on `DRY_RUN`; only the
exact MCDA signature `attempted=true`, `executed=false`, `reason="DRY_RUN"`
is normalized as simulated intent rather than an actual request. Each
observation preserves the original dictionary in `raw_execution`. Facts expose
`recorded_attempted_execution_events` separately from
`attempted_execution_events` and `simulated_execution_events`, with references
to all three source fields and a named interpretation. Missing reasons/outcomes
do not prove suppression. This exception never applies to agentic execution
records, and `executed=true` always remains an execution even alongside a
contradictory `DRY_RUN` marker.

The MCDA layer now uses its own execution-mode context (experiment `mode`),
not the agents' `agentic_mode`. The agentic policy is retained separately:
actual MCDA requests/execution are still forbidden during `authority-dry-run`
and during exclusive agentic `authority-live`. Aggregate execution outcomes
include both layers, with `execution_counts_by_layer` retaining their separate
counts; an actual MCDA execution cannot be hidden by a suppressed agentic
winner. Counts refer to logged events, not necessarily distinct actions, since
the MCDA may reuse a cached result across decision windows. The rules 2.0
report should be preserved: its false positives on confirmed MCDA simulations
are an auditor interpretation defect, not evidence of unsafe network actuation.

Each check records `check_id`, versioned `rule_id`, `dimension`, `status`,
`reason`, concrete `evidence`, `missing_fields`, and `source_refs` (artifact,
NDJSON line, JSON pointer and event ID where available). `verdict_support` maps
each dimension to its supporting check IDs. A check can pass while an optional
field is missing; `missing_fields` lists unavailable referenced fields, not
necessarily blocking prerequisites. Schema version 2.0 and rules version 2.1 distinguish
these results from earlier reports. Full proofs stay in JSON and Markdown;
the expanded trace will need context-budgeting before the next LLM explanation
phase. The frozen synthetic LLM inputs, prompt, schema and old results have
not been changed.

Preserve previous reports by choosing new output names. Existing reports are
protected unless `--overwrite` is explicitly supplied; input artifacts are
never valid output targets:

```bash
python3 -m llm_auditor "$DDOS_RUN" --mode audit \
  --output "$DDOS_RUN/deterministic_rules_v2_1.json" \
  --markdown-output "$DDOS_RUN/deterministic_rules_v2_1.md"

python3 -m unittest discover -s tests -p 'test_llm*.py' -v
```

The previously inspected 16-case corpus can also be checked without Ollama:

```bash
python3 -m llm_auditor.deterministic_campaign \
  --output deterministic_rules_v2_1_regression.json
```

This is now a **regression corpus**, not a fresh holdout for rule development.
Agreement with its declared oracles tests implementation behavior and does not
establish generalization, independent correctness, LLM quality, scalability or
real network effectiveness. New independent cases and manual review of real
traces are needed for those claims. The original frozen LLM campaign below is
retained separately for reproducibility.

## LLM modes

The explanation mode gives the deterministic verdict to the LLM and asks it
only for a grounded explanation:

```bash
python3 -m llm_auditor experiments/results/<run> \
  --mode explain \
  --model qwen3.5:9b \
  --ollama-url http://127.0.0.1:12434
```

The evaluation mode hides the deterministic verdict and measures whether the
LLM independently reaches the same classification. It is experimental and
must not control mitigation:

```bash
python3 -m llm_auditor experiments/results/<run> \
  --mode evaluate \
  --model qwen3.5:9b \
  --ollama-url http://127.0.0.1:12434
```

Both LLM modes request an Ollama JSON Schema response and use temperature 0,
seed 42, a 4096-token context, and `keep_alive=0` by default. The generated
JSON records the inference parameters and Ollama timing counters.

## Synthetic protocol campaign

The protocol campaign isolates six declared fixtures: `AGREED` as claim
winner, `WAITING_PROPOSALS`, `AGREED` as authorized non-winner,
`CORROBORATED`, `VETOED`, and benign `NORMAL`. It evaluates each categorical
field independently and preserves the Ollama response, timing, parameters,
expected oracle, and exact comparison:

```bash
python3 -m llm_auditor.protocol_campaign \
  --model qwen3.5:9b \
  --ollama-url http://127.0.0.1:12434 \
  --seeds 42 \
  --output llm_protocol_campaign.json
```

After the single-seed pilot, seed stability can be checked with:

```bash
python3 -m llm_auditor.protocol_campaign \
  --model qwen3.5:9b \
  --ollama-url http://127.0.0.1:12434 \
  --seeds 1,7,42,2026,9999 \
  --output llm_protocol_campaign_seeds.json
```

These inputs are explicitly marked as `synthetic_protocol_fixture`. They test
whether the LLM applies the documented protocol semantics; they are not new
network experiments and provide no evidence about detection accuracy,
coordination scalability, or mitigation effectiveness. Repetitions over the
same fixtures are not independent network observations, so the output reports
descriptive exact-match rates and does not attach a confidence interval.

## Frozen post-development validation

`--suite holdout-v1` loads a versioned corpus of 16 new synthetic cases:
six nominal variations, four protocol violations, two scenario discrepancies,
two execution outcomes, and two incomplete-evidence cases. Nominal variations
derive from the development templates; this is post-development validation,
not an independently collected external benchmark. Local-flow cases require
one responsible domain and cross-domain cases require the two endpoints, in
accordance with the current flow-specific responsibility contract.

The corpus includes insufficient quorum, duplicate claim winners, an absent
veto, actuation despite dry-run, false-positive/false-negative decisions,
successful/failed execution, and unknown operational outcomes. Oracles and
their rationales are stored in `fixtures/holdout_v1.json`, but only each case's
`evidence` object reaches the LLM. Opaque fixture identifiers carry no verdict.

First materialize the pre-inference manifest without contacting Ollama:

```bash
python3 -m llm_auditor.protocol_campaign \
  --suite holdout-v1 \
  --model qwen3.5:9b \
  --seeds 42 \
  --manifest-only \
  --output holdout-v1-manifest.json
```

Then run the full corpus once, without changing the prompt after inspecting
individual failures:

```bash
python3 -m llm_auditor.protocol_campaign \
  --suite holdout-v1 \
  --model qwen3.5:9b \
  --ollama-url http://127.0.0.1:12434 \
  --seeds 42 \
  --output holdout-v1-seed42.json
```

The loader rejects changes to the pinned fixture file, Ollama client, prompt
template, or output schema. The inference baseline is commit `9d0e0ef`, with
temperature 0 and a 4096-token context. Reports record those checksums and a
checksum of the selected cases. Preserve the model digest and Ollama version
alongside the manifest. A filtered subset is explicitly marked; it must not
be presented as the complete corpus. Existing output files are protected
unless `--overwrite` is deliberately supplied. Results are checkpointed after
each response, so an interrupted or failed campaign retains completed cases.

This measures the frozen evaluator end to end: normalization, rule wording,
schema and LLM. A mismatch requires checking observation scope, oracle,
prompt ambiguity and model output; it is not automatically an intrinsic model
failure. In particular, missing observations are not proof of no execution,
and successful installation alone is not proof of effective mitigation.
Exact categorical agreement also does not establish factual grounding of the
explanatory prose, which requires separate review. No result from these
fixtures demonstrates real network scalability or operational effectiveness.
