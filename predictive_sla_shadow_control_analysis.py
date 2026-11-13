"""Characterize frozen online controls without turning no episodes into a pass.

Local activations retain the unchanged strict matcher. Joint evidence counts
distinct confirmed pairs, not independent alarms, votes, actions or trials.
"""

from __future__ import annotations

from collections import Counter

import predictive_sla_shadow_ramp_analysis as paired
import predictive_sla_shadow_protocol_v2 as protocol


MATCHING = paired.MATCHING
read_journal = paired.read_journal
check_artifacts = paired.check_artifacts


POLICY = dict(
    version="shadow-control-characterization/1",
    reference="complete_native_workload_csv; unchanged_two_sample_sustained_episode_policy",
    local_activations="unchanged_strict_one_to_one_matcher; unmatched_and_censored_retained",
    joint_evidence="distinct_confirmed_pair_witnesses; duplicate_observer_views_deduplicated",
    joint_followup="observation_based_12_second_horizon; two_samples_required_for_confirmation",
    missing_samples="incomplete_sidecar_reference_coverage_is_insufficient_not_zero_alarms",
    outside_reference="retain_separately; never_assume_complete_future_followup",
    result="characterization_only; completion_is_not_acceptance_or_promotion",
)
LIMITATIONS = [*paired.LIMITATIONS,
    "A control profile label does not guarantee absence of observed sustained crossings; all actual episodes are retained.",
    "No preventive signals in one fully observed window is not an independently established specificity or false-alarm rate.",
    "Distinct joint pair witnesses may be renewals of one warning and are not counts of independent alarms or actions.",
    "Signals without a sustained utilization episode concern the frozen laboratory proxy, not verified service-level false positives.",
    "Censored, missing-input and outside-reference evidence is not classified as a successful negative.",
]


def validate_local_pairs(subject, series, journals, publications):
    """Require a confirmed exact pair for every local reference evaluation."""
    native = dict(zip(series["timestamps_ns"], series["values"]))
    local, outside = {}, []
    for event in journals[subject["cid"]]:
        if event["kind"] != "LOCAL_EVALUATION":
            continue
        sample = event["record"]["sample"]
        ts = sample["ts_ns"]
        if ts not in native:
            if event["record"]["activation"]:
                outside.append(dict(observed_ns=ts, activation=True,
                    scope="OUTSIDE_NATIVE_REFERENCE", future_followup="UNKNOWN"))
            continue
        if (event.get("cid") != subject["cid"] or sample["cid"] != subject["cid"]
                or sample["port_id"] != subject["port_id"] or sample["utilization_ratio"] != native[ts]
                or ts in local):
            raise ValueError("avaliação local não corresponde à referência nativa única")
        pairs = [row for row in publications.values() if row["cid"] == subject["cid"]
                 and row["risk"]["observed_ns"] == ts]
        if (len(pairs) != 1 or pairs[0]["risk"]["record"] != event["record"]
                or pairs[0]["risk"]["processing_completed_ns"] != event["processing_completed_ns"]
                or pairs[0]["risk"]["forecast_available_ns"] != event["forecast_available_ns"]):
            raise ValueError("avaliação de controle sem um único par confirmado correspondente")
        local[ts] = event
    return local, outside


def classify_agreement(risk, agreement, subject_report, native, timestamps):
    observed = risk["observed_ns"]
    result = dict(witness_id=agreement["witness_id"], observer=agreement["observer"],
        risk_sha256=protocol.digest(risk), observed_ns=observed,
        agreement_observed_ns=agreement["consensus_completed_ns"], matched_episode_id=None,
        sampled_onset_margin_s=None)
    if observed not in native:
        return dict(result, status="OUTSIDE_REFERENCE_WINDOW", future_followup="UNKNOWN")
    if risk["record"]["sample"]["utilization_ratio"] != native[observed]:
        raise ValueError("risco do acordo de controle difere da referência nativa")
    episodes = subject_report["strict_activation_episodes"]["episodes"]
    future = [episode for episode in episodes if 0 < episode["onset_ts_ns"] - observed <= 12_000_000_000]
    if future:
        first = min(future, key=lambda episode: episode["onset_ts_ns"])
        margin = (first["onset_ts_ns"] - agreement["consensus_completed_ns"]) / 1e9
        return dict(result, matched_episode_id=first["episode_id"], sampled_onset_margin_s=margin,
            status="PRE_SAMPLED_ONSET" if margin > 0 else "AT_OR_AFTER_SAMPLED_ONSET",
            future_followup="OBSERVED_EPISODE")
    if any(episode["onset_ts_ns"] <= observed <= (
            episode["clear_confirmation_ts_ns"] or timestamps[-1]) for episode in episodes):
        return dict(result, status="INPUT_AT_OR_AFTER_EPISODE_ONSET", future_followup="OBSERVED_EPISODE")
    required = subject_report["strict_activation_episodes"]["policy"]["min_consecutive_breach_samples"]
    last_confirmable = timestamps[-required] if len(timestamps) >= required else 0
    if observed + 12_000_000_000 > last_confirmable:
        return dict(result, status="CENSORED_NO_COMPLETE_FOLLOWUP", future_followup="INCOMPLETE")
    return dict(result, status="NO_SUSTAINED_EPISODE_WITHIN_HORIZON", future_followup="COMPLETE")


def analyze_subject(config, subject, series, journals, publications, agreements):
    base = paired.analyze_subject(config, subject, series, journals, publications, agreements)
    local, outside = validate_local_pairs(subject, series, journals, publications)
    timestamps = series["timestamps_ns"]
    native = dict(zip(timestamps, series["values"]))
    observations = [classify_agreement(row["risks"][subject["cid"]], row, base, native, timestamps)
                    for row in agreements]
    counts = Counter(row["status"] for row in observations)
    ready = sum(event["record"]["status"] == "FORECAST_READY" for event in local.values())
    complete = (len(local) == len(timestamps) and ready == len(timestamps)
                and not base["local_activations_missing_from_reference"])
    strict = base["strict_activation_episodes"]
    unsupported = counts["NO_SUSTAINED_EPISODE_WITHIN_HORIZON"]
    censored = counts["CENSORED_NO_COMPLETE_FOLLOWUP"]
    outside_count = counts["OUTSIDE_REFERENCE_WINDOW"]
    if not complete:
        outcome = "INSUFFICIENT_EVIDENCE"
    elif strict["actual_episodes"]:
        outcome = "OBSERVED_SUSTAINED_CROSSING"
    elif strict["unmatched_activations"] or unsupported:
        outcome = "PREVENTIVE_SIGNALS_WITHOUT_SUSTAINED_EPISODE"
    elif strict["censored_activations"] or censored or outside_count or outside:
        outcome = "INCOMPLETE_WARNING_FOLLOWUP"
    else:
        outcome = "NO_PREVENTIVE_SIGNALS_OBSERVED"
    return dict(**{key: value for key, value in base.items() if key != "measurement_status"},
        measurement_status="CONTROL_OBSERVED" if complete else "INSUFFICIENT_EVIDENCE",
        control_observation=outcome, full_sidecar_reference_coverage=complete,
        forecast_ready_reference_samples=ready,
        local_activations_outside_reference=outside,
        observed_joint_pair_witnesses=len(observations) - outside_count,
        unsupported_joint_pair_witnesses=unsupported, censored_joint_pair_witnesses=censored,
        outside_reference_joint_pair_witnesses=outside_count,
        joint_witness_status_counts=dict(counts), joint_witness_observations=observations)


def analyze(config, run_id, series, journals):
    if (len(series) != len(config["subjects"])
            or set(journals) != {subject["cid"] for subject in config["subjects"]}
            or any(block["cid"] != subject["cid"] or block["port_id"] != subject["port_id"]
                   for subject, block in zip(config["subjects"], series))):
        raise ValueError("referências/journals de controle incompletos ou incompatíveis")
    publications = paired.validate_publications(config, run_id, journals)
    agreements = paired.joint_agreements(config, run_id, journals, publications)
    reports = [analyze_subject(config, subject, block, journals, publications, agreements)
               for subject, block in zip(config["subjects"], series)]
    complete = all(row["measurement_status"] == "CONTROL_OBSERVED" for row in reports)
    outcomes = {row["control_observation"] for row in reports}
    return dict(measurement_status="CONTROL_OBSERVED" if complete else "INSUFFICIENT_EVIDENCE",
        control_observation=next(iter(outcomes)) if len(outcomes) == 1 else "MIXED_OBSERVATIONS",
        independent_runs=1, correlated_ports=len(reports),
        distinct_joint_agreement_witnesses=len(agreements), domains=reports,
        control_characterization_policy=POLICY, matching_policy=paired.MATCHING,
        deadline_feasibility="UNKNOWN", authority_latency_ms=None, actuation_latency_ms=None,
        llm_latency_ms=None, false_alarm_rate=None, specificity=None,
        sla_protection_established=False, promotion_eligible=False, deployment_eligible=False,
        boundary=protocol.BOUNDARY, limitations=LIMITATIONS)
