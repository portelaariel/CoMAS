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
evaluation windows before making the risk active and consecutive clear windows
before clearing it. This separates forecast persistence from temporal
persistence and prevents a single forecast point from triggering policy.

The event records the subject, metric, SLA comparator and threshold,
observation window, every forecast and interval, first possible and likely
crossing times, confirming horizons, model identity, creation time and expiry.
It performs no ETCD write, LLM call or network actuation.

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

1. Build a timestamped port-utilization dataset with the configured capacity,
   missing-sample markers and reset handling.
2. Calibrate and evaluate Holt separately at 2, 4 and 6 steps. Each horizon
   must have held-out error metrics and its own residual interval. The current
   one-step DDoS residual scale must not be reused as multi-horizon uncertainty.
3. Connect the calibrated forecasts to `evaluate_sla_forecast` and expose
   shadow evaluations through a read-only endpoint and experiment timeline.
4. Publish only active, non-expired `PREDICTED_SLA_RISK` evidence to a separate
   ETCD prefix. Keep it out of the current DDoS proposal keys.
5. Add a predictive CoMAS protocol with typed proposals such as `PREVENT`,
   `OBSERVE`, `VETO` and `ABSTAIN`. Missing, stale, model-mismatched or
   topology-incompatible evidence must never be sent to an LLM.
6. Run the LLM only as a bounded advisor for valid agent disagreement. Its
   output must pass a deterministic schema and authority gate and must never
   invoke an actuator directly.
7. Validate in shadow, authority-dry-run and finally a canary with a reversible
   policy, cooldown, idempotent claim, TTL and rollback evidence.

## Evaluation criteria

Forecast evaluation must report error and interval coverage per horizon.
Operational evaluation must report SLA-risk precision/recall, warning lead
time, false preventive actions, consensus latency, optional LLM latency,
actuation latency, rollback success and SLA violations avoided. DDoS accuracy
and SLA-risk accuracy must remain separate result families.
