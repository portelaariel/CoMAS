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

### Recovering stopped collectors without modifying the pilot

Do not restart collectors whose writable histories still point to pilot
collection directories. These append-only histories are not necessarily the
immutable CSV copies used for training. With an existing protocol, the helper
validates the CSV paths and hashes recorded in each frozen model's
`training.source_series` (for example `frozen/port_utilization_domain0.csv`). It
separately records the current history hashes for preservation, without requiring
them to equal training hashes. Shadow settings, image, networks and mounts are
also checked without changing Docker or files. It requires stopped
`flow-predictor-0/1` from the standard deployment:

```bash
sudo -v
python3 scripts/recover_qos_runtime.py \
  --protocol "$PWD/experiments/results/qos-prospective-v1/protocol.json" \
  --output "$PWD/experiments/results/qos-prospective-v1/runtime-recovery-v1"
```

After `plan=READY`, repeat with `--apply` to create and start
`comas-qos-prospective-0/1`. The helper preserves the original immutable image,
all environment variables, read-only model mounts, REST ports and network names;
Docker assigns new container IPs. Both histories use fresh directories under
the output root. Original containers remain stopped and are not removed or
renamed. Custom deployments or changed training CSVs are refused, not rewritten.
Before starting either copy, the helper verifies its actual image, environment,
mounts and network membership. Both training sources and collection histories
must remain unchanged between planning and startup. Failures preserve a redacted
`recovery.json` and attempt to stop only the newly created containers; they are
never deleted.

`START_REQUESTED` confirms only Docker accepted the start request, not that APIs
or the traffic path are healthy. Restore Mininet and calibration rules separately,
then rerun the collection preflight. Do not freeze again or modify the frozen
forecast/evaluation code. This recovery helper does not change protocol settings
or fit models and is not part of the frozen forecast/evaluation code set.

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

## Confirmation protocol v2: one activation window

Protocol v2 changes only `activation_windows` from two to one. The threshold
remains 0.80, two consecutive forecast horizons are still required, clearing
still requires two windows, and observed episodes still require two breach
samples and two clear samples. It uses byte-identical copies of the v1 frozen
models; it does not refit or modify runtime CoMAS configuration. In particular,
the risk policy is evaluated offline, not published or applied online.

The policy was selected by looking at v1 results. V2 therefore records that
selection as **post-hoc** in `selection-analysis.json`, and requires a separate
12-run campaign collected after its own freeze. Its evaluator excludes pilot
and v1 CSVs, reused traces, invalid observations and overlapping runs. The two
ports are still correlated, and repeated runs share the same testbed.

V2 has separate Python entry points. Neither of the v1 frozen code files is
edited, so the old protocol can still be loaded and re-evaluated. Freeze v2
from the completed v1 campaign, not from a newly fitted model:

```bash
python3 predictive_sla_validation_v2.py freeze \
  --source-protocol "$PWD/experiments/results/qos-prospective-v1/protocol.json" \
  --source-campaign "$PWD/experiments/results/qos-prospective-v1/campaign" \
  --output "$PWD/experiments/results/qos-prospective-v2"

sudo -v
python3 scripts/collect_qos_validation_campaign_v2.py \
  --protocol "$PWD/experiments/results/qos-prospective-v2/protocol.json" \
  --preflight-only
```

The freeze recomputes v1's summary, checks its stored report and sources, copies
the models without fitting, and protects the original v1 artifacts by hash.
Existing output directories and overlapping v1/v2 destinations are refused.
Original artifacts must remain available and unchanged for v2 provenance checks.
Do not restart old collectors, refreeze v1 or change the frozen code during either
campaign. The safe, fresh-history shadow collectors used for v1 can remain running.

After preflight, use a persistent terminal and refresh the sudo ticket inside
that terminal. The existing Mininet session must remain alive:

```bash
sudo -v
python3 scripts/collect_qos_validation_campaign_v2.py \
  --protocol "$PWD/experiments/results/qos-prospective-v2/protocol.json" \
  --output "$PWD/experiments/results/qos-prospective-v2/campaign" \
  --allow-lab-traffic
```

V2 reuses the unchanged v1 traffic/cleanup implementation and the same exclusive
lock. It cannot collect concurrently with v1. The v1 run-record schema remains
unchanged; its protocol hash links each record to v2. No actuator, LLM, controller
restart, runtime reconfiguration or new Docker deployment is involved.

The primary analysis is `coverage90` with one activation window. `coverage95` is
interval sensitivity, while `coverage90-confirmation2` is a predeclared paired
reference with two windows on the **same new traces**, not an independent group.
All three must retain identical point forecasts and candidate decisions.

The fixed primary acceptance criteria require all 12 valid runs, no persistent
activations in stable-low/short-pulses, at least one eligible episode for each
ramp run and monitored port, pre-onset warnings for every eligible ramp episode,
and no unmatched or censored activations. These are conservative research gates
for this testbed, not universal SLA or safety guarantees. Window-level FP/FN,
WATCH and timestamp-based lead times remain visible even if the gates pass.
No minimum actuator/LLM timing budget is asserted or tested.

`status=COMPLETED` means trace integrity and collection completed;
`criteria=PASSED` separately reports the selected policy's shadow gates. Exit
codes are 0 for both passing, 2 for invalid/incomplete data and 3 for completed
data with failed policy criteria. Reports always retain `promotion_eligible=false`.
Neither status enables preventive mitigation. To regenerate a read-only report,
use `predictive_sla_validation_v2.py evaluate` with the protocol, campaign root
and a new `--output "$PWD/experiments/results/qos-prospective-v2/campaign-review.json"`.

## Supplementary post-hoc diagnostics (v2 remains unchanged)

`predictive_sla_diagnostics.py` separately diagnoses fresh coverage by an already
active alert and the predictions behind control activations. It does not change
the v1/v2 frozen code, model artifacts, one-to-one activation matching, official
criteria, report or runtime settings. A completed diagnostic is not a passed
policy: the original `criteria_status`, activation counts, FP/FN and WATCH remain
in its baseline block. The supplementary report always has
`promotion_eligible=false` and explicitly labels the analysis as post-hoc.

For each eligible observed episode, fresh coverage requires that the immediately
preceding observation has a scored forecast, a `PREDICTED_SLA_RISK` candidate,
and an active alert. Its age at onset must not exceed the existing protocol's
`quality.maximum_gap_s` (5 s). This uses a data-quality bound, not a validated
SLA response deadline. An active state without a renewed candidate does not
count. Missing/unscored or stale forecasts are explicitly unassessable; the
reported coverage denominator still includes all eligible episodes.

One alert with renewed forecasts may cover two observed episodes separated by
two clear observed samples. This is reported as `covered_without_new_activation`,
not another matched activation. The latest forecast's age is not a new warning
lead time, and neither metric establishes preventive effectiveness. Coverage
need not exceed activation-based anticipation: an earlier matched warning can
also lack a fresh candidate immediately before onset.

The tool re-evaluates the completed campaign and checks the stored v2 summary,
source records, CSVs, frozen model/code hashes and native replay signatures.
All scoring, priming and unscored-tail rules stay unchanged. For control
activations, it saves the point forecasts, Holt level/trend, actual future
observations, residuals and nearby states. Future observations are diagnostic
ground truth only, never forecasting inputs. It does not fit or try alternative
Holt settings, make LLM calls, generate traffic or actuate.

```bash
python3 predictive_sla_diagnostics.py \
  --protocol "$PWD/experiments/results/qos-prospective-v2/protocol.json" \
  --campaign-root "$PWD/experiments/results/qos-prospective-v2/campaign" \
  --output "$PWD/experiments/results/qos-prospective-v2/supplementary-diagnostics-v1.json"
```

Only a new `supplementary-diagnostics*.json` directly inside the v2 protocol
directory is accepted; existing output and original artifacts are protected.
The console has at most nine lines; additional control details remain in JSON.
Preserve v2 results before choosing any next-model development experiment or
prospective v3 policy. This descriptive diagnostic is not a new validation run.

## Post-hoc damped-trend sensitivity (offline development only)

`predictive_sla_damping_study.py` compares the frozen coverage90 point forecasts
with additive damped Holt variants after the v2 failures have been inspected.
The fixed sensitivity grid is `phi = 1.00, 0.98, 0.95, 0.90, 0.80`. These are
engineering comparison settings, not empirically justified operating values;
the tool reports all of them without fitting, ranking, selecting or deploying
a variant. V2 traces are now development data for this alternative, not an
independent holdout. The original v2 `NOT_PASSED` result is never replaced.

The state update and forecast are additive damped Holt:

```text
level_t = alpha*y_t + (1-alpha)*(level_(t-1) + phi*trend_(t-1))
trend_t = beta*(level_t-level_(t-1)) + (1-beta)*phi*trend_(t-1)
prediction_(t+h) = max(0, level_t + (phi + ... + phi^h)*trend_t)
```

These recursions follow the additive damped implementation in the
[official statsmodels source](https://www.statsmodels.org/stable/_modules/statsmodels/tsa/holtwinters/model.html).
No statsmodels installation is needed. The same first-observation level, zero
initial trend, per-horizon alpha/beta, priming, rounding and per-series reset
as the frozen model are retained. With `phi=1`, every scored point, candidate,
activation, clearing, confusion count and episode match must reproduce the
native frozen backtest; any mismatch stops the study. Alpha/beta are not
refitted and may not be optimal for damped variants. Smaller phi also damps
falling trends and can change alert clearing; it is not assumed to lower every
forecast or improve every metric.

Changed predictions require newly calibrated intervals. This point-only study
does **not** borrow the original conformal radii, fabricate confidence bounds,
score WATCH or claim interval coverage. Two consecutive point-forecast horizons,
threshold 0.80, one-window activation, two-window clearing, and the original
observed-episode matcher stay fixed. WATCH and NORMAL both interrupt/clear the
native point-candidate persistence, so omitting WATCH does not change that path.
Future samples are used only to compute forecast errors and observed outcomes,
never to update a predictor or choose phi.

The report retains official results, source/code hashes, aggregate and per-run/
profile metrics, losses/gains in episode anticipation, and forecast context at
each baseline control activation. It distinguishes correlated port/episode
counts from the 12 workload runs and saves only a new report, not a runtime
model. `selected_variant=null`, `deployment_eligible=false` and
`promotion_eligible=false` apply to every outcome. The output has seven console
lines; details remain in JSON.

```bash
python3 predictive_sla_damping_study.py \
  --protocol "$PWD/experiments/results/qos-prospective-v2/protocol.json" \
  --campaign-root "$PWD/experiments/results/qos-prospective-v2/campaign" \
  --output "$PWD/experiments/results/qos-prospective-v2/damping-sensitivity-v1.json"
```

Only a new `damping-sensitivity*.json` directly inside the v2 protocol directory
is accepted. Original protocol, models, summaries and CSVs are protected and
checked before/after replay. A completed study is not a passing validation.
Any subsequent model choice needs separate training/calibration and a frozen
prospective experiment on newly collected traces.

## Joint damped-Holt training and recalibration (offline development)

`train_qos_damped_holt_model.py` fits a **separate experimental artifact** from
the completed, sealed v1 campaign. Repetitions 1 and 2 (eight workload runs)
select parameters; repetition 3 (four runs) calibrates new intervals. Each
workload's two correlated ports stay together in one partition, and model
states reset at each port/run boundary. No samples are concatenated between
runs. V1 has already been inspected, so neither partition is an independent
test. V2 data are not read, fitted, or relabeled as a passing validation.

For each 4/8/12-second nominal horizon, joint train-only grid search uses
`alpha = 0.10, 0.20, 0.35, 0.50, 0.70, 0.90`,
`beta = 0, 0.05, 0.10, 0.20, 0.35, 0.50`, and
`phi = 0.80, 0.90, 0.95, 0.98, 1.00`. This is a development search grid, not a
claim that these values are optimal operating parameters. The loss averages
per-run MSE within each profile, then weights the four profiles equally;
port/window errors are pooled within their workload, not counted as independent
runs. Exact ties prefer less damping, then smaller alpha/beta. `phi=1` remains
eligible; the grid does not force damping. The report retains every candidate
and a train-selected undamped reference with separately recalibrated intervals.

After parameter selection, absolute-residual split-conformal radii are computed
anew on calibration runs at nominal coverage 0.90. Original pilot radii are
never borrowed. Reported calibration coverage is in-sample descriptive coverage,
not held-out coverage or a formal operational guarantee for dependent traces.
Observed timestamp spacing remains in provenance: horizons are sample-step
forecasts with nominal two-second sampling, not resampled exact-time targets.
Lower forecast MSE does not by itself establish better SLA anticipation.

The tool requires all twelve v1 runs and an exact reproduction of the original
campaign summary. Protocol/model/CSV/summary and code hashes are verified before
and after fitting. It saves a development specification, model and report only
to a **new sibling** `qos-damped-development*` directory; source directories and
existing output are refused. `qos_damped_holt.py` uses the distinct type
`damped_holt_qos_multihorizon`, rejected by the native Holt loader. No runtime
registration, traffic, network calls, threshold/persistence tuning, LLM, or
actuation is performed. No dependencies beyond the existing Python standard
library are required. `promotion_eligible=false`, `deployment_eligible=false`
and `test_evaluated=false` remain mandatory. A separately frozen campaign on
newly collected traces is the next evaluation phase, not part of this command.

```bash
python3 train_qos_damped_holt_model.py \
  --protocol "$PWD/experiments/results/qos-prospective-v1/protocol.json" \
  --campaign-root "$PWD/experiments/results/qos-prospective-v1/campaign" \
  --output "$PWD/experiments/results/qos-damped-development-v1"
```

The console contains eight lines. Training/calibration provenance, full grid
results and limitations remain in `qos-damped-holt-evaluation.json` and
`development-spec.json`; no prospective-test metrics are fabricated.

## Replay of the trained damped model (inspected v2 development data)

`predictive_sla_damped_replay.py` compares that existing trained artifact with
the frozen original coverage90 Holt on all twelve already inspected v2 runs.
It performs no fitting or recalibration and preserves the threshold 0.80,
two consecutive point-forecast horizons, one-window activation, two-window
clearing and original sustained-episode matcher. Because v2 failures informed
the damping family, this is **post-hoc development diagnosis**, not an
independent test or a replacement of the official v2 `NOT_PASSED` result.

The original replay must reproduce native predictions, interval-derived WATCH,
candidate/persistent confusion and episode matches before the comparison is
published. The trained path uses `MultiHorizonDampedHoltForecaster` and its new
v1-calibrated radii; native Holt must not be used to silently ignore `phi`.
Both paths reset at every port/run boundary and retain identical priming and
unscored tails. Future values are scoring labels only. Forecast errors and
empirical interval coverage concern common scored v2 windows, not the earlier
training/calibration scoring scope or independent coverage guarantees.

The report distinguishes strict pre-onset anticipation from the original
matcher's `at_or_after_episode_onset` activations, with late delays measured
from CSV timestamps. Late activations never become positive warning lead
times. Lost/gained anticipation retains observed episode identities; WATCH,
control activations, unmatched/duplicate/censored activations and per-profile/
run metrics remain separate. An already active alert can cover a later
episode without a new activation; this strict matcher does not award that
coverage as a fresh warning. Correlated ports/episodes are not independent runs.

It also checks the structural identity for equal-alpha, zero-beta 4/8-second
models: the short point forecasts coincide, so the two-horizon candidate
reduces to their smoothed level crossing 0.80. The 12-second forecast alone
cannot confirm a candidate. This diagnostic does not change the model or rule.

Training receipt/model/report, their v1 source lineage, original v2 results and
analysis code are checked before/after replay. Only a new `replay-v2*.json`
directly in the existing `qos-damped-development*` directory is accepted;
overwrites and source targets are refused. The seven console lines summarize
original/trained anticipation, late/control alarms, paired losses/gains and
the structural check; full traces and limitations stay in JSON. A successful
command means the replay finished, not that SLA-warning criteria passed.
`independent_test=false`, `promotion_eligible=false` and
`deployment_eligible=false` remain mandatory. No traffic, runtime, ETCD, LLM
or preventive action is involved.

```bash
python3 predictive_sla_damped_replay.py \
  --protocol "$PWD/experiments/results/qos-prospective-v2/protocol.json" \
  --campaign-root "$PWD/experiments/results/qos-prospective-v2/campaign" \
  --development-root "$PWD/experiments/results/qos-damped-development-v1" \
  --output "$PWD/experiments/results/qos-damped-development-v1/replay-v2-v1.json"
```

## Train-only selection for early warnings (new development artifacts)

`train_qos_warning_model.py` addresses the mismatch between forecast MSE and
early warnings without changing any frozen model, protocol or result. It reuses
only v1 whole-run repetitions 1/2 for selection (eight workloads, two correlated
ports each). Repetition 3 (four workloads) calibrates residual intervals **after**
the parameter tuple is fixed. The command does not read v2 experiment data.
This objective was designed after inspecting v2 failures, so the work remains
post-hoc development, not an independent validation.

The bounded family shares one alpha/beta/phi tuple across the three horizons;
the existing 6 x 6 x 5 grid yields 180 joint candidates, rather than all
horizon-specific combinations. This is a deliberate restriction, not an
equivalence to the previous per-horizon MSE search. Zero beta and undamped
variants remain in the grid; no parameter is forced to produce a trend.

Feasibility requires zero training-control activations, zero censored activations
and at least one anticipated episode. Among feasible candidates the fixed
lexicographic order maximizes anticipated episode fraction, then minimizes
late activations, unmatched activations, candidate false-positive window rate,
and finally forecast MSE. Correlated ports are pooled per workload, runs receive
equal weight within profiles, and profiles receive equal weight. Anticipation
and lateness objectives concern the ramp profiles. There are no invented cost
weights or conditional-lead-time optimization; the priorities themselves are
explicit design choices, not proven optimal operating costs.

The threshold .80, two adjacent forecast horizons, one-window activation,
two-window clearing and sustained-episode matcher remain fixed. Original v1
official activation-2 results are checked for exact reproduction and preserved;
the new training reference is explicitly an activation-1 development replay.
Intervals during search are internal zero-radius placeholders, never published
as calibrated models. WATCH is not a selection target. The final radii are
recalibrated from repetition 3, and exact point/candidate/activation/episode
signatures must remain unchanged after calibration.

Only a **new sibling** `qos-warning-development*` directory is accepted; existing
directories and source targets are refused. The sealed spec and evaluation
contain hashes of original v1 sources and analysis code, the full candidate
table, run/profile weighting, paired episode losses/gains, misses and conditional
lead times. An infeasible search writes diagnostics with
`status=NO_FEASIBLE_CANDIDATE` and no model file, never an all-zero-alarm fallback.
A selected model uses the separate damped artifact type, is rejected by the
native loader, and is not automatically deployed. Earlier MSE artifacts and
their replay receipts remain untouched.

```bash
python3 train_qos_warning_model.py \
  --protocol "$PWD/experiments/results/qos-prospective-v1/protocol.json" \
  --campaign-root "$PWD/experiments/results/qos-prospective-v1/campaign" \
  --output "$PWD/experiments/results/qos-warning-development-v1"
```

The console contains seven lines; full details remain in
`qos-warning-evaluation.json`, `development-spec.json` and, only if feasible,
`qos-warning-model.json`. A completed search is not a criteria pass. Training
results and descriptive calibration coverage do not establish generalization,
operational safety or SLA protection. Independent test, promotion and deployment
flags stay false. A separately frozen evaluation on new traces is still required;
no runtime, LLM, ETCD, new traffic or preventive action occurs here.

## Prospective v3: fixed selected-warning model versus original Holt

`predictive_sla_validation_v3.py` freezes the **existing** warning-selected
artifact and original coverage90 Holt for twelve new workload runs (four
profiles, three rotated repetitions). It copies both model files byte-for-byte;
it does not select parameters again, fit, recalibrate or deploy either model.
The .80 threshold, two adjacent horizons, one-window activation, two-window
clearing and original sustained-episode definition/matching remain unchanged.
Both forecasters receive the same two correlated port series with per-run state
reset and the same priming/unscored tails. Observed episode identities must
coincide, but point forecasts, intervals and warning decisions need not.

The original v2 summary must reproduce its collected data exactly, even if
its criteria were `NOT_PASSED`. The warning-development receipt must match the
saved best feasible train-only selection and original v1 whole-run lineage.
Old pilot/v1/v2 data, protocols, models, receipts and analysis code are protected
by hashes; a v3 protocol must be frozen after development and the v2 collection
ended. Known previous CSVs cannot be reused as v3. New files are validated for
checksums, post-freeze timestamps, delivery/quality and non-overlapping run
intervals. Hashes prove artifact consistency, not independent experiments or
cryptographic attestation of genuine collection. Shared hardware, repeated
profiles and correlated ports still limit generalization claims.

```bash
python3 predictive_sla_validation_v3.py freeze \
  --source-protocol "$PWD/experiments/results/qos-prospective-v2/protocol.json" \
  --source-campaign "$PWD/experiments/results/qos-prospective-v2/campaign" \
  --development-root "$PWD/experiments/results/qos-warning-development-v1" \
  --output "$PWD/experiments/results/qos-prospective-v3"

sudo -v
python3 scripts/collect_qos_validation_campaign_v3.py \
  --protocol "$PWD/experiments/results/qos-prospective-v3/protocol.json" \
  --preflight-only
```

Freezing prints five lines; preflight prints one. If the development directory
has a different suffix, use the existing directory containing the three saved
warning artifacts; do not refit it to proceed. All output targets must be new.
V3 resides in a `qos-prospective-v3*` sibling directory. Freeze/evaluation are
offline; the separate collector requires the Linux testbed and explicit traffic
opt-in. Only after preflight is READY, run in a persistent session:

```bash
sudo -v
python3 scripts/collect_qos_validation_campaign_v3.py \
  --protocol "$PWD/experiments/results/qos-prospective-v3/protocol.json" \
  --output "$PWD/experiments/results/qos-prospective-v3/campaign" \
  --allow-lab-traffic
```

The collection uses the unchanged shadow-runtime safety checks, permanent
calibration forwarding rules, owned traffic/qdisc cleanup and shared v1/v2/v3
lock. It must not run concurrently with other workloads. It saves only new
campaign files, refuses resumes/overwrites, and preserves partial artifacts if
interrupted. Nominal offered traffic lasts 29.8 minutes, plus warmup/cleanup and
evaluation; this is not a runtime ETA. Neither forecasting artifact is loaded
into the live decision path, and no LLM, ETCD risk publication or preventive
actuation is introduced by this phase.

`campaign/campaign-summary.json` separates data completion from criteria
approval. The six existing criteria are applied to both variants separately;
top-level `criteria_status` and `checks` concern `selected_warning90` only.
`original_holt90` is the paired reference, not a mandatory correctness oracle
for a different forecaster. Reports retain candidate/active confusion, WATCH,
strict episode anticipation, unmatched/censored/late alarms, per-run/profile
metrics, conditional timestamp-based lead times, per-horizon forecast errors
and empirical interval coverage, plus paired lost/gained episodes.
Completion with failed criteria returns exit code 3; incomplete/invalid data
returns 2; complete data passing the primary criteria returns 0. None of these
states enables deployment or automatic promotion. A primary-model PASS alone
does not prove superiority, calibrated uncertainty guarantees, safe preventive
actions or SLA protection; no statistical superiority test is performed.

Re-evaluation never overwrites the official summary and cannot alter policy:

```bash
python3 predictive_sla_validation_v3.py evaluate \
  --protocol "$PWD/experiments/results/qos-prospective-v3/protocol.json" \
  --campaign-root "$PWD/experiments/results/qos-prospective-v3/campaign" \
  --output "$PWD/experiments/results/qos-prospective-v3/campaign-review-v1.json"
```

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
