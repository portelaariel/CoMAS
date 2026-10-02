# Predictive SLA risk pipeline

This document defines the incremental path from the current Holt-based DDoS
detector to preventive SLA protection. The new path is independent from DDoS
detection: it may reuse collectors and forecasting primitives, but it uses its
own evidence, states, policy and actuator contracts.

## Phase 1: deterministic shadow contract

`sla_risk.py` implements the first phase without changing the running CoMAS
services. It consumes multi-horizon forecasts and calibrated intervals and
classifies each horizon as:

- `CLEAR`: the interval remains within the SLA;
- `POSSIBLE`: only the uncertainty interval crosses the SLA;
- `LIKELY`: the point forecast crosses the SLA;
- `HIGH_CONFIDENCE`: the complete interval crosses the SLA.

A `PREDICTED_SLA_RISK` candidate requires `LIKELY` crossings in consecutive
horizons. `SlaRiskPersistence` then requires candidates in consecutive
evaluation windows before making the risk active and consecutive windows
without a new candidate before clearing it. `WATCH` is interval uncertainty,
not a renewal of the point-forecast candidate, so it participates in clearing
an old active state. This separates forecast persistence from temporal
persistence and prevents a single forecast point from triggering policy.

The event records the subject, metric, SLA comparator and threshold,
observation window, every forecast and interval, first possible and likely
crossing times, confirming horizons, model identity, creation time and expiry.
It performs no ETCD write, LLM call or network actuation.

## Phase 2: port-utilization dataset

`qos_telemetry.py` implements opt-in collection from OpenFlow port counters.
Every monitored `dpid:port` requires an explicit directional capacity in bits
per second. For a full-duplex link, `utilization_ratio` is calculated as
`max(rx_bps, tx_bps) / capacity_bps`; the directional and aggregate rates are
also retained for audit.

The append-only `port_utilization.csv` records both valid observations and
explicit quality markers: `PRIMING`, `COUNTER_RESET`, `MISSING_INTERVAL` and
`NON_MONOTONIC_TIMESTAMP`. Invalid observations retain their raw counters but
leave rates and utilization empty, so offline training cannot silently treat a
reset or collection gap as low utilization. The feature is disabled by
default and has no ETCD, agent, LLM or actuation path.

## Phase 3: horizon-specific Holt calibration

`qos_holt.py` and `train_qos_holt_model.py` implement the offline forecasting
stage. The trainer fits an independent Holt parameter pair for every requested
horizon, uses a separate calibration partition to obtain a finite-sample
split-conformal interval from absolute residuals, and reports accuracy and
interval coverage on a third held-out test partition. No test observation is
used to choose Holt parameters or interval radii.

The input manifest assigns each series segment explicitly to `train`,
`calibration`, or `test`. It also names the controller, port, time bounds and
source CSV. The loader rejects overlapping temporal partitions of the same
series, splits at invalid observations or collection gaps, and records source
SHA-256 hashes in the read-only model artifact. The runtime
`MultiHorizonHoltForecaster` produces the exact `horizon_steps`,
`predicted_value`, `lower_bound`, and `upper_bound` contract consumed by
`evaluate_sla_forecast`.

Two validation scopes are deliberately distinct:

- `pilot_single_run_temporal_split` validates mechanics but is never promotion
  evidence because all partitions originate from one experiment;
- `independent_run_holdout` reserves complete experiment runs for calibration
  and testing and is the required scope for a generalization claim.

For the two-domain testbed, ports `2:4` and `3:3` are the two observations of
the inter-domain link. They must remain separate time series, even though they
share one logical link subject. Multiple ports carrying the same flow are not
independent experimental repetitions.

## Phase 4: offline SLA-risk backtest

`backtest_sla_risk.py` replays only the held-out test partition through the
read-only forecaster, `evaluate_sla_forecast` and `SlaRiskPersistence`. Its
ground truth uses the same horizon rule as the policy: the observed utilization
must cross the SLA in the required number of consecutive forecast horizons.
The report separates point-forecast candidates, interval-only `WATCH` signals
and the persistent active state. It also measures warning lead time against
actual transitions into SLA violation using nominal sample intervals.
Persistent-state coverage and fresh
activation before a crossing are reported separately, so an old active state
cannot be presented as a new warning. Candidate FP/FN windows retain their
observed value, future ground truth and forecast horizons for diagnosis.

Multiple interval coverages can be compared without conflating them with the
point forecast. When Holt parameters are identical, interval coverage can
change `WATCH` and `HIGH_CONFIDENCE`, but it cannot change the raw
`PREDICTED_SLA_RISK` candidate, which depends on point forecasts. Persistent
clearing now counts consecutive non-candidates, including `WATCH`; wider
intervals cannot hold a stale active state by themselves.

Schema `comas-sla-risk-backtest/2` adds `episode_events` without changing those
legacy metrics. Under `observed-sla-episodes/1`, the default observed episode
is confirmed by two consecutive breach samples and starts retrospectively at
the first of them. Two non-breach samples clear it; single-sample dips do not
fragment an already confirmed episode. Unconfirmed spikes remain recorded
and are not erased from the instantaneous crossing or window metrics.

Match episodes chronologically to the earliest unused persistent activation
strictly before onset, within the maximum nominal forecast horizon measured
by actual CSV timestamps. Both episodes and activations have one-to-one
matches within each series. The report retains onset, confirmation, last
breach and clear timestamps, actual and nominal warning lead times, and all
matched/unmatched activation records. Activations at or after onset are not
preventive warnings. Priming and unscored tail windows supply no activation
opportunities. Unmatched activations lacking enough future observation to
cover the onset horizon and confirm a boundary episode are censored, not
declared false alarms. `activation_match_rate` excludes them and is not
window-classification precision. Onsets without any evaluated pre-onset
window within the horizon are ineligible, not missed warnings.

Keep episode parameters separate from forecast persistence and freeze them
before independent validation. Grouping an already inspected pilot is
exploratory; two sides of the same link do not provide independent trials.
This command remains offline and cannot publish proposals, consult an LLM
or invoke preventive actuators.

Example comparing two read-only artifacts:

```bash
python3 backtest_sla_risk.py qos-holt-manifest.json \
  --model coverage95=models/qos-holt-coverage95.json \
  --model coverage90=models/qos-holt-coverage90.json \
  --threshold 0.80 \
  --required-consecutive-horizons 2 \
  --activation-windows 2 \
  --clear-windows 2 \
  --episode-min-breach-samples 2 \
  --episode-clear-samples 2 \
  --output models/qos-sla-risk-backtest.json
```

Window-level classifications in this report are temporally dependent. They
must not be presented as independent experimental repetitions, and a
single-run temporal split remains ineligible for promotion.

## Phase 5: prospective validation with frozen artifacts

`predictive_sla_validation.py freeze` copies the two pilot models byte-for-byte
and seals a protocol before collecting new traces. Coverage 90% is the primary
artifact and coverage 95% a sensitivity comparison. Neither artifact is refit:
their original training scope and source hashes remain unchanged. Code hashes,
sampling (2 s), horizons (4/8/12 s), threshold (0.80), two consecutive horizons,
activation/clearing windows (2/2), and observed-episode policy (2/2) are frozen.
Checksums detect changes; they are not signatures or independent attestation.

The default campaign schedules four workloads in three repetitions, rotating
their order: stable low traffic, isolated two-second pulses, a slow ramp, and a
fast ramp. Each run has a low-rate warmup and recovery period. Total planned
measurement time is 29.8 minutes, plus process startup and command overhead.
The profile name is not a ground-truth label. In particular, counter sampling
can dilute or split a two-second pulse; episodes are derived from the measured
utilization, not from the intended source rate.

Prerequisites are the existing two-domain Mininet, fresh QoS telemetry for
`192.168.10.10/2:4` and `192.168.11.10/3:3`, capacity 100 Mbit/s, and the
persistent IPv4 calibration rules for h1/h8: cookie `0x51534c41`, priority
3100, zero timeouts, forward switch ports s1 `1→3`, s2 `3→4`, s3 `3→4`,
s4 `3→2`, with inverse rules for the reverse direction. The preflight checks
these rules but never installs or removes flows. CoMAS must have
`auto_mitigate=false`, `dry_run=true`, `agentic_mode=shadow`, live opt-in off,
actuation disabled, and zero live executions. Existing h1 shaping or iperf in
either host causes refusal rather than automatic cleanup.

On the Linux experiment server, freeze first and inspect the read-only
preflight. Use a new output directory; existing results are never overwritten:

```bash
PILOT_ROOT="/home/ubuntu/sdn-ariel/comas-predictive-sla/experiments/results/qos-continuous-static-v1-20260925T121303Z"
PROTOCOL_ROOT="$PWD/experiments/results/qos-prospective-v1"
python3 predictive_sla_validation.py freeze \
  --pilot-root "$PILOT_ROOT" --output "$PROTOCOL_ROOT"
sudo -v
python3 scripts/collect_qos_validation_campaign.py \
  --protocol "$PROTOCOL_ROOT/protocol.json" --preflight-only
```

After `preflight=READY`, run in a persistent terminal. Keep the repository
version unchanged between freezing, collecting, and evaluating. Collection
requires an explicit laboratory traffic opt-in:

```bash
python3 scripts/collect_qos_validation_campaign.py \
  --protocol "$PWD/experiments/results/qos-prospective-v1/protocol.json" \
  --output "$PWD/experiments/results/qos-prospective-v1/campaign" \
  --allow-lab-traffic
```

The collector creates its own bounded iperf processes (UDP port 5009) and a
tagged HTB qdisc `7a51:` on h1 solely to generate the planned workload. It
records the two monitored ports through GET requests, deduplicates timestamps,
and periodically rechecks the shadow configuration and namespace identity.
Normal completion, Ctrl-C, and SIGTERM preserve a sealed `run.json` and clean
up only these process groups and this qdisc. No global `pkill`, topology
restart, controller reconfiguration, ETCD write, LLM call, or mitigation occurs.
A crash, SIGKILL, or server reboot cannot guarantee cleanup: inspect the tagged
qdisc/processes before restarting; the next preflight refuses residual state.

Offline evaluation rejects missing/failed cases, changed CSVs, reused pilot
artifacts, overlapping runs, invalid observations, gaps above 5 s, or absent
boundary coverage. For stages lasting at least 10 s, it excludes the first 4 s
and requires mean utilization between 50% and 200% of the nominal shaped
rate/capacity. This deliberately broad delivery check detects broken traffic
paths without defining SLA ground truth or tuning forecasts. Rejected cases
remain visible rather than being silently segmented or counted as TN.

The collector writes `campaign-summary.json` after the planned runs. To inspect
partial data or regenerate an offline report without overwriting that summary:

```bash
python3 predictive_sla_validation.py evaluate \
  --protocol "$PWD/experiments/results/qos-prospective-v1/protocol.json" \
  --campaign-root "$PWD/experiments/results/qos-prospective-v1/campaign" \
  --output "$PWD/experiments/results/qos-prospective-v1/campaign-review.json"
```

Reports retain candidate FP/FN windows, WATCH, observed episodes, one-to-one
warnings, unmatched/censored activations, and timestamp-based lead times by
run and port. Both link ends are correlated; pooled window or episode counts
are descriptive, not independent trials. Repetitions share the same testbed,
so statistical independence is not guaranteed. These new traces test the
frozen pilot artifacts prospectively, but do not convert their training scope
to `independent_run_holdout`, enable promotion, or demonstrate application SLA
protection, Internet-scale generalization, LLM decisions, or preventive action.

## Initial measurable scope

The first online experiment should use one metric and one reversible action:

- metric: port `utilization_ratio`, derived from OpenFlow byte-counter deltas
  and an explicitly configured link capacity;
- sampling interval: 2 seconds, matching the current collector;
- horizons: 2, 4 and 6 steps (4, 8 and 12 seconds);
- risk confirmation: two consecutive forecast horizons and two consecutive
  evaluation windows;
- initial mode: shadow only;
- later reversible action: queue/rate policy with TTL and automatic rollback.

The link capacity must be configured metadata. It must not be inferred from
the largest observed rate, because doing so would silently move the SLA during
the experiment.

## Required next phases

1. Connect the calibrated forecasts to `evaluate_sla_forecast` and expose
   shadow evaluations through a read-only endpoint and experiment timeline.
2. Publish only active, non-expired `PREDICTED_SLA_RISK` evidence to a separate
   ETCD prefix. Keep it out of the current DDoS proposal keys.
3. Add a predictive CoMAS protocol with typed proposals such as `PREVENT`,
   `OBSERVE`, `VETO` and `ABSTAIN`. Missing, stale, model-mismatched or
   topology-incompatible evidence must never be sent to an LLM.
4. Run the LLM only as a bounded advisor for valid agent disagreement. Its
   output must pass a deterministic schema and authority gate and must never
   invoke an actuator directly.
5. Validate in shadow, authority-dry-run and finally a canary with a reversible
   policy, cooldown, idempotent claim, TTL and rollback evidence.

## Evaluation criteria

Forecast evaluation must report error and interval coverage per horizon.
Operational evaluation must report SLA-risk precision/recall, warning lead
time, false preventive actions, consensus latency, optional LLM latency,
actuation latency, rollback success and SLA violations avoided. DDoS accuracy
and SLA-risk accuracy must remain separate result families.
