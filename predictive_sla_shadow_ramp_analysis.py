"""Offline paired timing witnesses for a single controlled shadow ramp.

The unchanged two-sample episode matcher supplies sampled onsets, not physical
crossing times. Availability timestamps are not substituted by sample times.
"""

from __future__ import annotations

import json
from pathlib import Path

import predictive_sla_shadow_protocol_v2 as protocol
import predictive_sla_validation as provenance
from sla_episode_evaluation import evaluate_episodes


MATCHING = dict(
    local_warning="unchanged_chronological_one_to_one_persistent_activation_matcher",
    joint_warning="earliest_unused_recorded_fresh_agreement_per_sampled_port_episode",
    agreement_deduplication="proposal_hashes_and_pair_revisions_keep_earliest_observer_receipt",
    eligible_input="local_risk_observation_pre_onset_within_frozen_12_second_horizon",
    availability="signed_onset_minus_actual_stage_timestamp; positive_only_is_pre_onset",
    ack_order="client_ack_may_follow_another_readers_agreement_receipt",
    independence="one_run_two_correlated_ports_not_independent_votes_or_trials",
)
LIMITATIONS = [
    "Sampled utilization threshold episodes are a laboratory proxy, not measured service-level SLA failures.",
    "Onset is the first recorded breach in a two-sample confirming streak, determined retrospectively.",
    "Physical crossing time between counter windows is unknown; positive sampled-onset margin is not a real deadline guarantee.",
    "Both ports observe one shared link and do not provide independent confirmations or statistical repetitions.",
    "Local activation matching remains strict; fresh joint agreement timing is a separate supplementary measurement.",
    "An activation input timestamp before onset does not imply its forecast, publication or agreement was available before onset.",
    "Client acknowledgement is not the server commit time and may arrive after a peer has read the committed pair.",
    "Per-stage durations overlap and must not be added; authority, LLM and actuation are not measured.",
    "One ramp cannot establish generalization, false-positive rates, deadline feasibility or SLA protection; v4 results are unchanged.",
]


def read_journal(path):
    rows = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.endswith("\n"):
                raise ValueError(f"journal incompleto: {path.name}")
            rows.append(json.loads(line))
    return rows


def check_artifacts(root, summary, subjects=None):
    if subjects is not None:
        required = {"manifest.json", "preflight-transport.ndjson", "launcher-transport.ndjson"}
        for subject in subjects:
            required.update({subject["cid"] + suffix for suffix in (".ndjson", "-summary.json", "-transport.ndjson")})
        if not required <= summary["artifacts_sha256"].keys():
            raise ValueError("inventário de artefatos shadow incompleto")
    for name, checksum in summary["artifacts_sha256"].items():
        path = root / name
        if (Path(name).name != name or path.is_symlink() or not path.is_file()
                or provenance.digest_file(path) != checksum):
            raise ValueError(f"artefato shadow mudou/fora do diretório: {name}")


def summary_stats(values):
    return dict(count=len(values), values=values, minimum=min(values) if values else None,
                mean=sum(values) / len(values) if values else None, maximum=max(values) if values else None)


def validate_publications(config, run_id, journals):
    publications = {}
    for subject in config["subjects"]:
        cid = subject["cid"]
        for event in journals[cid]:
            if event["kind"] != "PAIR_PUBLICATION":
                continue
            risk, item, ack = event["risk"], event["proposal"], event["pair_publication_ack_ns"]
            if event.get("cid") != cid or event.get("commit_outcome") != "CONFIRMED":
                raise ValueError("publicação sem confirmação válida")
            protocol.positive_ns(event["pair_mod_revision"])
            protocol.positive_ns(ack)
            # Validate the prepared pair at proposal preparation, not at a later
            # offline wall clock. Delayed acks do not renew observation expiry.
            protocol.verify_pair(config, run_id, subject, risk, item, item["evaluated_ns"])
            if ack < item["evaluated_ns"]:
                raise ValueError("ACK anterior à preparação da proposta")
            identity = protocol.digest(risk)
            if identity in publications:
                raise ValueError("risco com mais de uma confirmação registrada")
            publications[identity] = event
    return publications


def joint_agreements(config, run_id, journals, publications):
    witnesses = {}
    for observer, events in journals.items():
        for event in events:
            if event["kind"] != "SHADOW_CONSENSUS" or event["assessment"]["status"] != "SHADOW_PREVENT_AGREED":
                continue
            received, completed = event["peer_snapshot_received_ns"], event["consensus_completed_ns"]
            protocol.positive_ns(received)
            protocol.positive_ns(completed)
            if completed < received:
                raise ValueError("consenso anterior ao recebimento do snapshot")
            snapshot = event["peer_snapshot"]
            expected = protocol.consensus(config, run_id, snapshot, received)
            if expected != event["assessment"]:
                raise ValueError("acordo não corresponde ao snapshot/contrato congelados")
            risks, acks = {}, {}
            for subject in config["subjects"]:
                cid = subject["cid"]
                risk = snapshot["values"][f"risks/{cid}"]
                identity = protocol.digest(risk)
                publication = publications.get(identity)
                if publication is None or publication["pair_mod_revision"] != snapshot["mod_revisions"][f"risks/{cid}"]:
                    raise ValueError("acordo não aponta para um par confirmado neste piloto")
                if snapshot["values"][f"proposals/{cid}"] != publication["proposal"]:
                    raise ValueError("proposta do snapshot difere do par confirmado")
                risks[cid], acks[cid] = risk, publication["pair_publication_ack_ns"]
            identity = protocol.digest(dict(proposals=expected["evidence_sha256"], revisions=expected["pair_mod_revisions"]))
            witness = dict(witness_id=identity, observer=observer, consensus_completed_ns=completed,
                           peer_snapshot_received_ns=received, risks=risks, acknowledgements_ns=acks)
            if identity not in witnesses or completed < witnesses[identity]["consensus_completed_ns"]:
                witnesses[identity] = witness
    return sorted(witnesses.values(), key=lambda row: (row["consensus_completed_ns"], row["witness_id"]))


def margin(onset, timestamp):
    return None if timestamp is None else (onset - timestamp) / 1e9


def stages(onset, observed, forecast, ack, agreement=None):
    return dict(observed_ns=observed, forecast_available_ns=forecast, pair_publication_ack_ns=ack,
        agreement_observed_ns=agreement,
        observed_input_lead_s=margin(onset, observed), forecast_available_margin_s=margin(onset, forecast),
        publication_ack_margin_s=margin(onset, ack), agreement_available_margin_s=margin(onset, agreement),
        observation_to_forecast_ms=None if forecast is None else (forecast - observed) / 1e6,
        observation_to_pair_ack_ms=None if ack is None else (ack - observed) / 1e6,
        observation_to_agreement_ms=None if agreement is None else (agreement - observed) / 1e6,
        agreement_before_client_ack=None if agreement is None or ack is None else agreement < ack)


def analyze_subject(config, subject, series, journals, publications, agreements):
    cid = subject["cid"]
    values, timestamps = series["values"], series["timestamps_ns"]
    native = dict(zip(timestamps, values))
    evaluations = {}
    for event in journals[cid]:
        if event["kind"] != "LOCAL_EVALUATION":
            continue
        record, timestamp = event["record"], event["record"]["sample"]["ts_ns"]
        if event.get("cid") != cid:
            raise ValueError("journal local contém outro domínio")
        if timestamp not in native:
            continue
        sample = record["sample"]
        if sample["port_id"] != subject["port_id"] or sample["utilization_ratio"] != native[timestamp]:
            raise ValueError("amostra do agente difere da referência CSV sob o mesmo timestamp")
        if timestamp in evaluations:
            raise ValueError("avaliação local duplicada sob o mesmo timestamp")
        evaluations[timestamp] = event
    observations = [dict(index=index, persistent_activation=evaluations[timestamp]["record"]["activation"])
                    for index, timestamp in enumerate(timestamps)
                    if timestamp in evaluations and evaluations[timestamp]["record"]["status"] == "FORECAST_READY"]
    policy = config["policy"]
    episodes = evaluate_episodes(values=values, observations=observations, timestamps_ns=timestamps,
        series_id=series["series_id"], cid=cid, port_id=subject["port_id"], comparator="MAX",
        threshold=policy["threshold"], sample_interval_s=2, max_horizon_steps=6,
        min_breach_samples=policy["episode_min_breach_samples"], clear_samples=policy["episode_clear_samples"])
    results, used_agreements = [], set()
    for episode in episodes["episodes"]:
        onset = episode["onset_ts_ns"]
        warning = None
        if episode["activation_ts_ns"] is not None:
            evaluation = evaluations[episode["activation_ts_ns"]]
            matching = [publication for publication in publications.values()
                        if publication["cid"] == cid and publication["risk"]["observed_ns"] == episode["activation_ts_ns"]]
            if len(matching) != 1 or matching[0]["risk"]["record"] != evaluation["record"]:
                raise ValueError("ativação não possui um único par confirmado correspondente")
            publication = matching[0]
            if publication["risk"]["forecast_available_ns"] != evaluation["forecast_available_ns"]:
                raise ValueError("timestamp da previsão difere do risco publicado")
            risk_identity = protocol.digest(publication["risk"])
            exact = [row for row in agreements if protocol.digest(row["risks"][cid]) == risk_identity]
            available = exact[0]["consensus_completed_ns"] if exact else None
            warning = dict(stages(onset, episode["activation_ts_ns"], evaluation["forecast_available_ns"],
                                  publication["pair_publication_ack_ns"], available),
                           risk_sha256=risk_identity,
                           exact_pair_agreement_status=("NO_RECORDED_AGREEMENT_FOR_ACTIVATION_PAIR" if available is None else
                                                        "PRE_SAMPLED_ONSET" if available < onset else "AT_OR_AFTER_SAMPLED_ONSET"),
                           pair_mod_revision=publication["pair_mod_revision"])
        # Keep the FIRST recorded eligible witness, including a late one. Never
        # choose a later/better result or reuse it for another episode in this port.
        eligible = [row for row in agreements if row["witness_id"] not in used_agreements
                    and 0 < onset - row["risks"][cid]["observed_ns"] <= 12_000_000_000
                    and row["risks"][cid]["observed_ns"] in native]
        witness = eligible[0] if eligible else None
        joint = None
        if witness is not None:
            used_agreements.add(witness["witness_id"])
            risk = witness["risks"][cid]
            if risk["record"]["sample"]["utilization_ratio"] != native[risk["observed_ns"]]:
                raise ValueError("risco do acordo difere da referência observada")
            joint = dict(stages(onset, risk["observed_ns"], risk["forecast_available_ns"],
                                witness["acknowledgements_ns"][cid], witness["consensus_completed_ns"]),
                         witness_id=witness["witness_id"], observer=witness["observer"],
                         risk_sha256=protocol.digest(risk),
                         eligibility_basis="fresh_candidate_input_not_new_activation")
        joint_status = ("NO_RECORDED_FRESH_AGREEMENT" if joint is None else
                        "PRE_SAMPLED_ONSET" if joint["agreement_available_margin_s"] > 0 else
                        "AT_OR_AFTER_SAMPLED_ONSET")
        results.append(dict(episode_id=episode["episode_id"], onset_ts_ns=onset,
            confirmation_ts_ns=episode["confirmation_ts_ns"], left_censored=episode["left_censored"],
            right_censored=episode["right_censored"], local_activation=warning,
            strict_activation_matched=episode["detected"], joint_agreement=joint,
            joint_timing_status=joint_status, physical_crossing_time_ns=None))
    sample_start, sample_end = timestamps[0], timestamps[-1]
    missing = [event["record"]["sample"]["ts_ns"] for event in journals[cid]
               if event["kind"] == "LOCAL_EVALUATION" and event["record"]["activation"]
               and sample_start <= event["record"]["sample"]["ts_ns"] <= sample_end
               and event["record"]["sample"]["ts_ns"] not in native]
    return dict(cid=cid, port_id=subject["port_id"], samples=len(values),
        native_samples_seen_by_sidecar=len(evaluations), native_samples_not_seen_by_sidecar=len(values) - len(evaluations),
        local_activations_missing_from_reference=missing,
        measurement_status=("INSUFFICIENT_EVIDENCE" if missing or not observations else
                            "PAIRED" if results else "NO_OBSERVED_SUSTAINED_CROSSING"),
        delivery_checks=series["delivery_checks"], strict_activation_episodes=episodes,
        episode_timings=results,
        joint_pre_sampled_onset=sum(r["joint_timing_status"] == "PRE_SAMPLED_ONSET" for r in results),
        joint_at_or_after_sampled_onset=sum(r["joint_timing_status"] == "AT_OR_AFTER_SAMPLED_ONSET" for r in results),
        joint_without_recorded_agreement=sum(r["joint_timing_status"] == "NO_RECORDED_FRESH_AGREEMENT" for r in results),
        agreement_available_margin_s=summary_stats([r["joint_agreement"]["agreement_available_margin_s"]
                                                   for r in results if r["joint_agreement"] is not None]))


def analyze(config, run_id, series, journals):
    if len(series) != len(config["subjects"]) or set(journals) != {s["cid"] for s in config["subjects"]}:
        raise ValueError("séries/journals incompletos")
    if any(block["cid"] != subject["cid"] or block["port_id"] != subject["port_id"]
           for subject, block in zip(config["subjects"], series)):
        raise ValueError("identidades das séries divergem da configuração")
    publications = validate_publications(config, run_id, journals)
    agreements = joint_agreements(config, run_id, journals, publications)
    reports = [analyze_subject(config, subject, block, journals, publications, agreements)
               for subject, block in zip(config["subjects"], series)]
    statuses = {report["measurement_status"] for report in reports}
    return dict(measurement_status="PAIRED" if statuses == {"PAIRED"} else "INSUFFICIENT_EVIDENCE",
        independent_runs=1, correlated_ports=len(reports), distinct_joint_agreement_witnesses=len(agreements),
        matching_policy=MATCHING, domains=reports, deadline_feasibility="UNKNOWN",
        authority_latency_ms=None, actuation_latency_ms=None, llm_latency_ms=None,
        sla_protection_established=False, promotion_eligible=False, deployment_eligible=False,
        boundary=protocol.BOUNDARY, limitations=LIMITATIONS)
