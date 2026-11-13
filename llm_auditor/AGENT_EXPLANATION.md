# Supplementary English explanations of domain-agent decisions

This optional module explains **why each recorded agent proposed its action**,
how the proposals relate to the recorded collective decision, and the distinction
between authorization, claim ownership, execution and the episode audit outcome.
It is not a replacement for `certificate-explain/2.9` and does not change that
contract, its Portuguese explanations, or any agent/runtime/authority code.

## Scope and evidence

- Input is an existing audit JSON and its run's `timeline.ndjson`.
- By default, one audited agent event is selected per episode, preferring actual
  execution, then claim ownership, authorization, final decisions, then recency.
  This is a selected-event explanation, not an exhaustive negotiation history.
- `--event-id` can select an audited disagreement or waiting event explicitly.
- Each proposal is enriched from its producer's retained proposal snapshot only
  if CID, flow, model, window, observation timestamp and creation timestamp all
  match, and the summarized fields agree. Another revision/window is never used.
- Full proposal snapshots can supply observed/predicted rates, Holt deviation,
  threshold, persistence and score criteria. Producer policy is taken only from
  matching producer snapshots, never from defaults or another observer's policy.
  Such policy is observed with the snapshot, not proven to be creation-time policy.
- Missing evidence stays explicitly unavailable. If only a summarized proposal
  remains, an exact numerical explanation cannot be reconstructed for that agent.
- References resolve to timeline lines/JSON pointers or the input audit episode.
  SHA256 hashes bind the current input files, evidence and prompt; they do not
  retroactively prove experiment-time provenance or independent audit correctness.

The LLM is asked for concise English narratives, not fixed sentence copies. It
does not cast votes, choose the coordinator, authorize mitigation or call ETCD,
Docker, controllers or FlowBlocker. Only the configured Ollama `/api/chat` endpoint
is contacted. No traffic experiment is repeated, and no model is retrained.

## Prepare evidence without inference

Run from the repository root. Choose a **new output directory** for every command:

```bash
python3 -B -m llm_auditor.agent_explanation --audit /absolute/path/fresh-live-audit-v1.json --prepare-only --output /absolute/path/agent-evidence-v1
```

Review `evidence.json`, especially the proposal `detail_basis`,
`unavailable_fields`, the selected `event_id`, and `source_refs`. The file also
contains the exact planned LLM requests. No network request is made in this mode.

## Generate the English narrative

```bash
python3 -B -m llm_auditor.agent_explanation --audit /absolute/path/fresh-live-audit-v1.json --ollama-url http://127.0.0.1:12436 --model qwen3.5:9b --num-ctx 6144 --output /absolute/path/agent-explanation-v1
```

Optional `--run-dir` locates a relocated copy of the run. Otherwise, the directory
in the existing audit is used. Optional `--timeout-s` defaults to 180 seconds.
There are no automatic retries. Errors/truncation preserve evidence and any raw
response received in the new output directory. Existing outputs are never replaced.
Context checks use a heuristic UTF-8 estimate before sending, and observed token
counts after completion; neither proves input completeness by itself.

Outputs:

- `evidence.json`: source hashes, selected events, references, unavailable fields,
  and exact inference payloads.
- `narrative.json`: raw responses, structural checks, errors and review status.
- `presentation.md`: English narrative followed by its evidence packet.

## Review before presenting

Success is `GENERATED_REQUIRES_REVIEW`, **not** `ACCEPTED_STRUCTURALLY` under the
certified contract. Structural validation checks event identity, section shape
and allowed references. It does **not** certify factual accuracy, English quality,
causal inference or the absence of hallucinations. All generated prose remains
`prose_factually_verified=false` and `manual_review_required=true`.

Before presenting, compare each sentence and number to the cited packet. Ensure
that missing evidence is disclosed; scores are not described as probabilities;
permission is not confused with execution; episode-level outcome is not attributed
to an unexecuted event; and dissent, FAIL or UNKNOWN findings remain visible.
Reject or separately correct unsupported prose. Do not edit the certified audit
to make it agree with a narrative. Present this as an additional explanation of
recorded deterministic agent behavior, not as an LLM-generated network decision.

## Tests

```bash
python3 -B -m unittest discover -s tests -p 'test_agent_decision_explanation.py' -v
```

These are offline tests with mocked inference, including failure cases. A real
Ollama output still needs inspection on the target machine before the demo.
