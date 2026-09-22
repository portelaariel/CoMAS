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

## Evidence-based deterministic verifier (rules 2.2)

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

Rules 2.2 correct the MCDA state semantics used by the verifier. `MITIGATE`
requires both the configured confirming-domain count and, when the runtime
configuration is present, a score at or above `decision_threshold`.
`CORROBORATED` is an intermediate score-band state: it requires at least one
confirming domain and a score satisfying
`alert_threshold <= score < decision_threshold`. It is therefore valid for a
`CORROBORATED` event to contain all configured domains; full domain
corroboration alone does not force `MITIGATE`. The adapter retains the event
score and the two thresholds from `collaboration.config`, with source
references to the original timeline row.

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
necessarily blocking prerequisites. Schema version 2.0 and rules version 2.2 distinguish
these results from earlier reports. Full proofs stay in JSON and Markdown;
the explanation phase now uses the compact certificate described below instead
of sending the expanded trace. The frozen synthetic LLM inputs, evaluator
client, evaluation prompt, schema and old results have not been changed.

Preserve previous reports by choosing new output names. Existing reports are
protected unless `--overwrite` is explicitly supplied; input artifacts are
never valid output targets:

```bash
python3 -m llm_auditor "$DDOS_RUN" --mode audit \
  --output "$DDOS_RUN/deterministic_rules_v2_2.json" \
  --markdown-output "$DDOS_RUN/deterministic_rules_v2_2.md"

python3 -m unittest discover -s tests -p 'test_llm*.py' -v
```

The previously inspected 16-case corpus can also be checked without Ollama:

```bash
python3 -m llm_auditor.deterministic_campaign \
  --output deterministic_rules_v2_2_regression.json
```

This is now a **regression corpus**, not a fresh holdout for rule development.
Agreement with its declared oracles tests implementation behavior and does not
establish generalization, independent correctness, LLM quality, scalability or
real network effectiveness. New independent cases and manual review of real
traces are needed for those claims. The original frozen LLM campaign below is
retained separately for reproducibility.

## LLM modes

### Compact explanation certificate (version 1.0)

`--mode certificate` runs locally without Ollama. It adds
`explanation_certificate`, `certificate_ledger`, and `certificate_context` to
each audited episode. The certificate preserves the five deterministic verdicts,
execution/claim context, per-layer counts, and every rule/status group, including
`FAIL` and `UNKNOWN`. Repeated checks are grouped only after verification;
votes are never pooled. Each group has an evidence ID such as `E06` and one
example witness. Its witness is not a description of all member events.

The ledger maps evidence IDs to every original `check_id`, which resolves to
the full check and its `source_refs`. Long witness strings/lists are explicitly
abbreviated; the full evidence is unchanged on disk. Hashes bind the certificate
to the supplied audit data, but are not signatures or independent verification
of the network. Logged-event counts do not imply distinct actions or agents.

First inspect the certificate and its context estimate, using fresh filenames:

```bash
python3 -m llm_auditor "$DDOS_RUN" --mode certificate \
  --output "$DDOS_RUN/certificate_v1.json" \
  --markdown-output "$DDOS_RUN/certificate_v1.md"

jq '.episodes[] | {
  verdicts: .explanation_certificate.verdicts,
  coverage: .explanation_certificate.coverage,
  context: .certificate_context
}' "$DDOS_RUN/certificate_v1.json"
```

The estimate is `ceil(UTF8 message bytes / 3)`, plus 900 output tokens and a
256-token template/safety reserve. It is a heuristic, not model-specific
tokenization or proof that Ollama retained the full input. An oversized estimate
prevents sending the request; no failure/unknown group is silently removed to
make it fit. If it does not fit, inspect the certificate before choosing a
larger `--num-ctx` on the inference machine. The new client also requires normal
completion (`done=true`, `done_reason="stop"`), valid token counters, an output
below its token limit, and adequate observed context reserve. These checks
detect obvious context/output problems, not every possible silent truncation
or semantically unfinished sentence.

The updated explanation mode sends **only this certificate**, not observations,
full proofs, event IDs or the ledger. `certificate_explanation.py` is separate
from the byte-frozen evaluator in `ollama.py`. The response contains `summary`
and five `dimensions`, each with an exact verdict echo, `explanation`, and
`evidence_ids`. Validation rejects changed categorical values, nonexistent or
wrong-dimension references, and omission of a `FAIL`/`UNKNOWN` group citation.
`ACCEPTED_STRUCTURALLY` does not prove that the free prose is factually correct:
`grounding_validation.prose_factually_verified` remains false and manual review
is required. There is no model-generated confidence score or mitigation action.

For the Mac inference machine accessed through the server's reverse tunnel:

```bash
python3 -m llm_auditor "$DDOS_RUN" --mode explain \
  --model qwen3.5:9b \
  --ollama-url http://127.0.0.1:12435 \
  --output "$DDOS_RUN/certificate_explain_v1.json" \
  --markdown-output "$DDOS_RUN/certificate_explain_v1.md"

jq '.episodes[].llm_explanation | {
  status, error, result, grounding_validation, completion, context_budget, metrics
}' "$DDOS_RUN/certificate_explain_v1.json"
```

Rejected/failed inference leaves the certificate, deterministic proof, error,
and raw response (when received) in the report, with status `REJECTED` and CLI
exit code 2. It never replaces the deterministic verdict. Preserve this report
and choose another output name for a retry. Old explanation reports used a
different output contract; keep them separately rather than overwriting them.

### Experimental evaluation

The evaluation mode hides the deterministic verdict and measures whether the
LLM independently reaches the same classification. It is experimental and
must not control mitigation. The frozen baseline is unchanged; certificates
and previous LLM results are also excluded from its input:

```bash
python3 -m llm_auditor experiments/results/<run> \
  --mode evaluate \
  --model qwen3.5:9b \
  --ollama-url http://127.0.0.1:12434
```

Both LLM modes request an Ollama JSON Schema response and use temperature 0,
seed 42, a 4096-token context, and `keep_alive=0` by default. The generated
JSON records the inference parameters and Ollama timing counters.
Explanation reports additionally retain completion metadata, the raw response,
certificate/prompt hashes and structural-reference validation. Agreement with
the deterministic labels in this mode is constrained by the schema and must
not be reported as independent LLM classification accuracy.

## Explanation regression: violations and missing evidence

`explanation_campaign.py` prepares certificates from the existing, previously
inspected synthetic corpus. It does not read or modify a network run. By default
it selects six critical cases, verified against their declared deterministic
oracles before inference:

- `h07`: insufficient mitigation votes and a contradictory NORMAL proposal.
- `h08`: two owners under the explicitly declared single-claim invariant.
- `h13`: VETOED reported despite explicitly absent veto evidence.
- `h14`: actuation reported despite dry-run; execution and observed effectiveness
  can coexist with a protocol violation in this synthetic example.
- `h15`: missing prerequisite/execution evidence; unknown is not zero or suppression.
- `h16`: execution recorded without operational observations; effectiveness remains UNKNOWN.

The default is one serial inference per case, seed 42, temperature 0, context
6144, and `keep_alive=0`. It uses the unchanged certificate explanation prompt
and client, not the frozen independent evaluator. Synthetic origin is explicitly
included in these certificates. Case titles, declared oracles, rationales and
manual review targets stay outside the LLM input.

First prepare the complete manifest without contacting Ollama:

```bash
python3 -m llm_auditor.explanation_campaign \
  --manifest-only \
  --output "$DDOS_RUN/critical_explanation_manifest_v1.json"

jq '.summary | {cases_prepared, oracle_mismatches, estimated_context_oversized}' \
  "$DDOS_RUN/critical_explanation_manifest_v1.json"
```

Then run the explanation regression through the Mac inference tunnel:

```bash
python3 -m llm_auditor.explanation_campaign \
  --model qwen3.5:9b \
  --ollama-url http://127.0.0.1:12435 \
  --num-ctx 6144 \
  --output "$DDOS_RUN/critical_explanations_seed42_v1.json"

jq -r '
  "Status: \(.campaign_status)",
  "Accepted structurally: \(.summary.structurally_accepted)/\(.summary.evaluations_completed)",
  "Manual review pending: \(.summary.pending_manual_review)",
  (.evaluations[] | "\(.case_id): \(.llm_explanation.status)")
' "$DDOS_RUN/critical_explanations_seed42_v1.json"
```

The inference report itself saves its prepared manifest before any network
request, then checkpoints each response. It records dataset/source/prompt/schema
hashes and reads Ollama version/model digest when available; unavailable metadata
is marked with warnings. Existing files are protected unless `--overwrite` is
explicitly requested. Use `--case h07 --case h15` to select a smaller initial
subset; any such subset remains explicitly identified.

Malformed/truncated or improperly cited outputs are rejected; remaining cases
continue when a raw response exists. A no-response transport failure stops the
campaign with `PARTIAL_ERROR`, retaining prior responses. Ctrl+C during inference
marks it `INTERRUPTED`. Preserve partial results and choose new output names for
retrying missing cases; the module does not silently repeat saved responses.
An oracle mismatch or oversized context estimate prevents all inference with
status `BLOCKED_PRECHECK`.

`ACCEPTED_STRUCTURALLY` is not approval of the explanation's meaning. Each
accepted answer remains `manual_review.status=PENDING`. Review whether it actually
describes each FAIL/UNKNOWN cause, preserves FINAL versus valid decision, treats
execution observations as stronger than intended dry-run, distinguishes unknown
outcome from NOT_APPLICABLE, and avoids claiming real network measurements from
synthetic records. Full text/proofs remain in JSON; Markdown shows the concise
verdicts, review targets and generated explanations without the expanded source
reference lists. No classification-accuracy metric is produced. This inspected
corpus is regression material, not a new independent benchmark; the original
frozen evaluator, fixture file and previous results are unchanged.

### Causal explanation certificate (version 2.8)

The version 1 and earlier v2 reports remain preserved. Version 2.8 retains the
verifier-derived causal index and rules 2.2 without changing the frozen
independent evaluator. For each of the five verifier dimensions it records an exact `cause_code`, the
decisive evidence IDs, compact causal facts, and supporting (non-decisive) IDs.
Only failing groups are decisive for `INCONSISTENT`; only unresolved groups are
decisive for `INSUFFICIENT_EVIDENCE`. Known false/zero values remain evidence,
whereas null optional fields are removed from causal facts and cannot be named
as the cause unless the verifier explicitly lists them in `unavailable_fields`.

The causal LLM contract sends a projection containing only decisive causal
facts, rather than the v1 witnesses that may contain unrelated optional nulls.
It must repeat the deterministic verdict, cause code, causal statement, and
the complete ordered list of decisive IDs for every dimension. The prompt
explicitly distinguishes no applicable actuation from unavailable operational
observations and requires a recorded execution count for `EXECUTED`. This
prevents the structural errors observed in the first manual review. An
answer that names a null field omitted from the causal projection is rejected.
Each per-dimension `explanation` must now equal the verifier-generated causal
statement exactly: prefixes, suffixes, paraphrases and additional claims are
rejected. This prevents an answer from repeating the right cause and then
contradicting it in appended prose. The generated summary remains free text and
therefore remains pending human review.
Unknown execution is also kept distinct from a confirmed execution whose
operational outcome alone is unavailable.

Version 2.8 additionally records `comparative_alignment` as an independent
post-experiment finding. It uses the frozen MCDA comparison captured during
authority evaluation and reports `ALIGNED`, `DIVERGENT`, or
`INSUFFICIENT_EVIDENCE`. This finding does not change protocol consistency or
scenario correctness. When the agents reach `AGREED` with the required
MITIGATE votes while the observational MCDA remains `CORROBORATED` below its
decision threshold, the deterministic causal statement explains that
distinction explicitly instead of treating it as a protocol failure.
When the comparison was unavailable because the visible MCDA snapshot belonged
to another window, the verdict remains `INSUFFICIENT_EVIDENCE`, but the cause
is reported specifically as `agent_mcda_window_mismatch_at_authority`. Future
runtime records also include `published_ns`, which distinguishes the beginning
of MCDA evaluation from the moment its result became visible to comparators.
The comparison profile retains the latest result per domain as
`final_alignment`, counts every authority-time comparison, and groups
non-aligned observations with their windows and occurrence counts. Consequently,
a final `ALIGNED` result can explicitly report
`final_alignment_after_transient_divergence` instead of erasing an earlier
same-window disagreement. This temporal profile remains independent of the
protocol verdict.

Prepare and inspect the version 2 manifest without contacting Ollama:

```bash
python3 -m llm_auditor.causal_explanation_campaign \
  --manifest-only \
  --output "$DDOS_RUN/critical_causal_manifest_v2_8.json"

jq '{
  status: .campaign_status,
  summary,
  causes: [
    .cases[] | {
      case_id,
      protocol: .causal_review.protocol_consistency.cause_code,
      execution: .causal_review.execution_status.cause_code,
      effectiveness: .causal_review.operational_effectiveness.cause_code,
      comparison: .causal_review.comparative_alignment.cause_code
    }
  ]
}' "$DDOS_RUN/critical_causal_manifest_v2_8.json"
```

After the manifest passes its local prechecks, run the six explanations through
the Mac inference tunnel:

```bash
python3 -m llm_auditor.causal_explanation_campaign \
  --model qwen3.5:9b \
  --ollama-url http://127.0.0.1:12435 \
  --num-ctx 6144 \
  --output "$DDOS_RUN/critical_causal_explanations_seed42_v2_8.json"

jq -r '
  "Status: \(.campaign_status)",
  "Accepted structurally: \(.summary.structurally_accepted)/\(.summary.evaluations_completed)",
  "Manual review pending: \(.summary.pending_manual_review)",
  (.evaluations[] | "\(.case_id): \(.llm_explanation.status)")
' "$DDOS_RUN/critical_causal_explanations_seed42_v2_8.json"
```

The v2 report is a synthetic explanation regression, not a new accuracy result
or network experiment. A structural acceptance shows that the model preserved
the verifier's categorical output and citations; it does not approve the prose.
The v1 certificate hash is retained as `derived_from_certificate_v1_sha256`, and
the complete proof/ledger remains available for provenance and manual review.

After the synthetic causal regression is reviewed, apply the same contract to a
completed real experiment with a fresh filename. `causal-explain` re-runs the
deterministic verifier, attaches the version 2.8 certificate and sends only its
causal projection to Ollama; it never enters the runtime or actuates mitigation:

```bash
python3 -m llm_auditor "$DDOS_RUN" \
  --mode causal-explain \
  --model qwen3.5:9b \
  --ollama-url http://127.0.0.1:12435 \
  --num-ctx 6144 \
  --output "$DDOS_RUN/causal_explain_real_v2_8.json" \
  --markdown-output "$DDOS_RUN/causal_explain_real_v2_8.md"

jq '.episodes[] | {
  deterministic: {
    protocol_consistency,
    scenario_correctness,
    decision_stage,
    execution_status,
    operational_effectiveness
  },
  explanation_status: .llm_explanation.status,
  causal_statements_match: .llm_explanation.grounding_validation.causal_statements_match_exactly,
  omitted_null_fields_absent: .llm_explanation.grounding_validation.omitted_null_fields_absent,
  result: .llm_explanation.result
}' "$DDOS_RUN/causal_explain_real_v2_8.json"
```

The real-run report remains a post-experiment explanation of recorded evidence,
not an independent proof that the logs are complete or that mitigation was
effective. A structurally accepted answer still requires review of its free-text
summary; the five verifier explanations and the independent comparative
explanation are exact deterministic statements.

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
