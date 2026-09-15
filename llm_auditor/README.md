# CoMAS LLM Auditor

This package audits completed CoMAS experiments without entering the runtime
decision or mitigation path. It reads `metadata.json`, `summary.json`, and
`timeline.ndjson`; it never publishes to ETCD, elects an executor, calls
FlowBlocker, or installs OpenFlow rules.

The deterministic mode is the source of truth:

```bash
python3 -m llm_auditor experiments/results/<run> --mode audit
```

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
