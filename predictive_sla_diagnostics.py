#!/usr/bin/env python3
"""Post-hoc, offline diagnostics; never replace the frozen v2 evaluation."""

from __future__ import annotations

import argparse
import json
import math
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Sequence

import predictive_sla_validation as v1
import predictive_sla_validation_v2 as v2
from backtest_sla_risk import _actual_future_outcome, backtest_model
from qos_holt import MultiHorizonHoltForecaster, QosHoltModel
from sla_episode_evaluation import validate_timestamps
from sla_risk import SLA_RISK_EVENT_TYPE, SlaRiskPersistence, SlaRiskPolicy, evaluate_sla_forecast


ROOT = Path(__file__).resolve().parent
SCHEMA = "comas-predictive-sla-supplementary-diagnostics/1"
COVERAGE_POLICY = {
    "version": "fresh-active-coverage/1",
    "scope": "posthoc_descriptive_not_a_replacement_acceptance_criterion",
    "signal": "latest_evaluated_sample_before_onset_is_active_and_candidate",
    "freshness": "age_at_onset_le_protocol_quality_maximum_gap_s",
    "continuity": "latest_sample_must_be_the_immediately_preceding_observation",
    "missing": "missing_or_stale_forecast_is_unassessable_not_zero",
    "reuse": "an_active_alert_with_a_fresh_candidate_can_cover_multiple_observed_episodes",
    "timing": "latest_renewal_age_is_not_new_activation_lead_time",
}
LIMITATIONS = [
    "The supplementary coverage definition was chosen after inspecting v2 failures and is post-hoc.",
    "Frozen activation matching, criteria, false alarms, and v2 NOT_PASSED results remain unchanged.",
    "Freshness uses the existing data-quality maximum gap, not a validated actuator or LLM deadline.",
    "Candidate forecasts concern the frozen horizons; coverage is descriptive, not proof of preventive protection.",
    "Observed onsets are retrospective; a renewed alert is not a new independently anticipated episode.",
    "Both ports and successive windows are correlated; no independence or generalization claim is made.",
    "Future observations shown for diagnosis are never inputs to the forecasting or alert state.",
]


def replay_series(model: QosHoltModel, series: Dict[str, Any], policy: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Replay exactly the scored v2 windows, checking native frozen signals."""
    expected, expected_points, expected_candidates = backtest_model(model=model, series=[series], **policy)
    values, timestamps = series["values"], series["timestamps_ns"]
    validate_timestamps(timestamps, len(values))
    risk_policy = SlaRiskPolicy(metric=model.metric, comparator="MAX", threshold=policy["threshold"],
                               horizons_steps=tuple(h.horizon_steps for h in model.horizons),
                               required_consecutive_horizons=policy["required_consecutive_horizons"])
    forecaster = MultiHorizonHoltForecaster(model)
    persistence = SlaRiskPersistence(activation_windows=policy["activation_windows"],
                                    clear_windows=policy["clear_windows"])
    maximum_horizon = max(risk_policy.horizons_steps)
    rows, points, candidates = [], {}, {}
    risk_started_index = None
    for index, observed in enumerate(values):
        forecasts = forecaster.update(observed)
        if not forecasts or index + maximum_horizon >= len(values):
            continue
        timestamp = timestamps[index]
        evaluation = evaluate_sla_forecast(
            policy=risk_policy, cid=series["cid"], subject_type="port", subject_id=series["port_id"],
            observed_value=observed, window_id=index + 1, observation_ns=timestamp,
            sample_interval_s=model.sample_interval_s, forecasts=forecasts,
            model_id=model.resolved_model_id(), model_type=model.model_type,
            created_ns=timestamp, ttl_s=maximum_horizon * model.sample_interval_s)
        state = persistence.update(evaluation)
        activation = state["active"] and state["transitioned"]
        if activation:
            risk_started_index = index
        elif not state["active"]:
            risk_started_index = None
        candidate = evaluation["decision"] == SLA_RISK_EVENT_TYPE
        actual = _actual_future_outcome(values, index, risk_policy)
        classification = ("TP" if actual["positive"] else "FP") if candidate else (
            "FN" if actual["positive"] else "TN")
        rows.append(dict(
            index=index, ts_ns=timestamp, observed_value=observed, decision=evaluation["decision"],
            candidate=candidate, active=state["active"], activation=bool(activation),
            transitioned=state["transitioned"], clear_streak=state["clear_streak"],
            risk_started_index=risk_started_index, classification=classification,
            forecast_horizons=evaluation["forecast"]["horizons"],
            holt_states=[dict(horizon_steps=h.horizon_steps, alpha=h.alpha, beta=h.beta,
                              level=forecaster._states[h.horizon_steps]["level"],
                              trend=forecaster._states[h.horizon_steps]["trend"])
                         for h in model.horizons],
            future_observations=[dict(horizon_steps=h.horizon_steps,
                                      nominal_horizon_s=h.horizon_steps * model.sample_interval_s,
                                      observed_horizon_s=(timestamps[index + h.horizon_steps] - timestamp) / 1e9,
                                      actual_value=values[index + h.horizon_steps],
                                      predicted_value=forecast["predicted_value"],
                                      residual=values[index + h.horizon_steps] - forecast["predicted_value"])
                                 for h, forecast in zip(model.horizons, forecasts)]))
        key = series["series_id"], index
        points[key] = tuple(float(h["predicted_value"]) for h in forecasts)
        candidates[key] = candidate
    expected_activations = [row["activation_index"] for row in expected["series"][0]["episode_events"]["activations"]]
    if (points != expected_points or candidates != expected_candidates
            or [row["index"] for row in rows if row["activation"]] != expected_activations
            or sum(row["transitioned"] and not row["active"] for row in rows)
            != expected["series"][0]["persistent_active"]["clear_transitions"]):
        raise ValueError("replay diagnóstico diverge dos sinais congelados")
    return rows


def evaluate_fresh_coverage(*, rows: Sequence[Dict[str, Any]], episodes: Sequence[Dict[str, Any]],
                            timestamps_ns: Sequence[int], maximum_age_s: float,
                            maximum_horizon_s: float) -> List[Dict[str, Any]]:
    """Use only the latest pre-onset forecast, not an old activation in isolation."""
    if (not math.isfinite(maximum_age_s) or not 0 < maximum_age_s <= maximum_horizon_s
            or not math.isfinite(maximum_horizon_s)):
        raise ValueError("limite de atualização inválido")
    validate_timestamps(timestamps_ns, len(timestamps_ns))
    by_index = {}
    for row in rows:
        index = row["index"]
        if (isinstance(index, bool) or not isinstance(index, int) or not 0 <= index < len(timestamps_ns)
                or index in by_index or row["ts_ns"] != timestamps_ns[index]
                or not isinstance(row["candidate"], bool) or not isinstance(row["active"], bool)):
            raise ValueError("observação de replay inválida ou duplicada")
        by_index[index] = row
    results = []
    for episode in episodes:
        onset = episode["onset_index"]
        if (isinstance(onset, bool) or not isinstance(onset, int) or not 0 <= onset < len(timestamps_ns)
                or episode["onset_ts_ns"] != timestamps_ns[onset]
                or not isinstance(episode["eligible"], bool) or not isinstance(episode["detected"], bool)):
            raise ValueError("início de episódio inválido")
        latest = by_index.get(onset - 1)
        age_s = None if latest is None else (episode["onset_ts_ns"] - latest["ts_ns"]) / 1e9
        assessable = bool(episode["eligible"] and latest is not None and 0 < age_s <= maximum_age_s)
        covered = bool(latest["candidate"] and latest["active"]) if assessable else None
        if not episode["eligible"]:
            reason = "episode_ineligible_under_frozen_definition"
        elif latest is None:
            reason = "latest_pre_onset_evaluation_unavailable"
        elif not assessable:
            reason = "latest_pre_onset_forecast_stale"
        elif not latest["candidate"]:
            reason = "active_without_renewed_candidate" if latest["active"] else "no_renewed_candidate"
        elif not latest["active"]:
            reason = "candidate_not_yet_active"
        else:
            reason = "fresh_candidate_and_active_alert"
        results.append(dict(
            episode_id=episode["episode_id"], onset_index=onset, onset_ts_ns=episode["onset_ts_ns"],
            cid=episode["cid"], port_id=episode["port_id"], eligible=episode["eligible"],
            strict_anticipated=episode["detected"], matched_activation_index=episode["activation_index"],
            matched_activation_lead_time_s=episode["warning_lead_time_s"],
            coverage_assessable=assessable, fresh_active_coverage=covered, coverage_reason=reason,
            covered_without_new_activation=covered is True and not episode["detected"],
            latest_renewal_age_s=age_s,
            latest_pre_onset_evaluation=latest))
    return results


def _summarize(series: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    episodes = [e for item in series for e in item["episodes"] if e["eligible"]]
    covered = sum(e["fresh_active_coverage"] is True for e in episodes)
    return dict(
        eligible_episodes=len(episodes), strict_anticipated=sum(e["strict_anticipated"] for e in episodes),
        freshly_covered=covered, coverage_rate_over_all_eligible=covered / len(episodes) if episodes else None,
        eligible_not_assessable=sum(not e["coverage_assessable"] for e in episodes),
        covered_without_new_activation=sum(e["covered_without_new_activation"] for e in episodes),
        anticipated_without_latest_renewal=sum(e["strict_anticipated"] and e["fresh_active_coverage"] is not True
                                             for e in episodes),
        control_activations=sum(len(item["control_activation_diagnostics"]) for item in series),
        frozen_signal_crosscheck=True)


def _sources_snapshot(protocol: Dict[str, Any], protocol_path: Path, campaign: Path) -> Dict[str, str]:
    files = [protocol_path, campaign / "campaign-summary.json"]
    files.extend(protocol_path.parent / entry["path"] for entry in protocol["models"].values())
    for case in protocol["cases"]:
        root = campaign / case["case_id"]
        files.append(root / "run.json")
        record = json.loads((root / "run.json").read_text(encoding="utf-8"))
        for source in record["sources"]:
            path = (root / source["csv"]).resolve()
            if not path.is_relative_to(root.resolve()):
                raise ValueError("fonte fora da execução")
            files.append(path)
    return {str(path.resolve()): v1.digest_file(path) for path in files}


def build_report(protocol_path: Path, campaign: Path) -> Dict[str, Any]:
    protocol_path, campaign = protocol_path.resolve(), campaign.resolve()
    analysis_sha256 = v1.digest_file(Path(__file__))
    protocol = v2.load_protocol(protocol_path)
    verified = v2.evaluate_campaign(protocol_path, campaign)
    summary_path = campaign / "campaign-summary.json"
    if verified["status"] != "COMPLETED":
        raise ValueError("diagnóstico requer 12 execuções v2 válidas e encerradas")
    if json.loads(summary_path.read_text(encoding="utf-8")) != verified:
        raise ValueError("relatório v2 diverge da reavaliação congelada")
    before = _sources_snapshot(protocol, protocol_path, campaign)
    models = {name: QosHoltModel.load(protocol_path.parent / entry["path"])
              for name, entry in protocol["models"].items()}
    variants = {name: [] for name in verified["models"]}
    for case, expected in zip(protocol["cases"], verified["cases"]):
        case_root = campaign / case["case_id"]
        subjects, record, hashes = v1._read_case(protocol, case, case_root)
        if hashes != expected["source_sha256"]:
            raise ValueError("sources v2 mudaram após a reavaliação congelada")
        for name, items in variants.items():
            reference = name == "coverage90-confirmation2"
            model = models["coverage90" if reference else name]
            policy = protocol["reference_policy"] if reference else protocol["policy"]
            for series, source in zip(subjects, record["sources"]):
                frozen = next(s for s in expected["models"][name]["series"] if s["series_id"] == series["series_id"])
                rows = replay_series(model, series, policy)
                by_index = {row["index"]: row for row in rows}
                episodes = evaluate_fresh_coverage(
                    rows=rows, episodes=frozen["episode_events"]["episodes"],
                    timestamps_ns=series["timestamps_ns"], maximum_age_s=protocol["quality"]["maximum_gap_s"],
                    maximum_horizon_s=max(h.horizon_steps for h in model.horizons) * model.sample_interval_s)
                controls = []
                if case["profile"] in ("stable-low", "short-pulses"):
                    for activation in frozen["episode_events"]["activations"]:
                        index = activation["activation_index"]
                        controls.append(dict(
                            frozen_activation=activation, evaluation=by_index[index],
                            horizon_ground_truth_scope="frozen_window_definition_not_sustained_episode",
                            context=[row for row in rows if abs(row["index"] - index) <= 2]))
                targets = {e["onset_index"] for e in episodes if e["eligible"] and not e["strict_anticipated"]}
                items.append(dict(
                    case_id=case["case_id"], profile=case["profile"], series_id=series["series_id"],
                    cid=series["cid"], port_id=series["port_id"],
                    source=dict(csv=str((case_root / source["csv"]).resolve()), sha256=source["sha256"],
                                index_policy="zero_based_data_row; CSV_header_is_line_1", csv_line_offset=2),
                    episodes=episodes, frozen_activations=frozen["episode_events"]["activations"],
                    missed_episode_context=[row for row in rows if any(abs(row["index"] - i) <= 6 for i in targets)],
                    control_activation_diagnostics=controls, frozen_signal_crosscheck=True))
    v2.load_protocol(protocol_path)
    if (_sources_snapshot(protocol, protocol_path, campaign) != before
            or v1.digest_file(Path(__file__)) != analysis_sha256):
        raise ValueError("sources v2 mudaram durante o diagnóstico")
    return v1.seal(dict(
        schema_version=SCHEMA, created_ns=time.time_ns(), status="DIAGNOSTIC_COMPLETED",
        scope="posthoc_supplementary_not_confirmatory_validation", promotion_eligible=False,
        git_commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        analysis_code_sha256=analysis_sha256, source_sha256=before,
        frozen_protocol_code_sha256=protocol["code_sha256"],
        baseline=dict(protocol_sha256=protocol["protocol_sha256"],
                      summary_sha256=before[str(summary_path.resolve())], status=verified["status"],
                      criteria_status=verified["criteria_status"], checks=verified["checks"],
                      models=verified["models"]),
        coverage_policy={**COVERAGE_POLICY, "maximum_age_s": protocol["quality"]["maximum_gap_s"]},
        models={name: dict(summary=_summarize(items), series=items) for name, items in variants.items()},
        limitations=list(LIMITATIONS)), "report_sha256")


def output_path(protocol_path: Path, output: Path) -> Path:
    output = output.resolve()
    if (output.exists() or output.parent != protocol_path.resolve().parent
            or output.suffix != ".json" or not output.name.startswith("supplementary-diagnostics")):
        raise ValueError("use um novo supplementary-diagnostics*.json dentro do diretório v2")
    return output


def console_lines(report: Dict[str, Any]) -> List[str]:
    baseline = report["baseline"]
    lines = [f"official_v2={baseline['status']} criteria={baseline['criteria_status']} unchanged=true"]
    for name, result in report["models"].items():
        s = result["summary"]
        lines.append(f"{name}: activations={s['strict_anticipated']}/{s['eligible_episodes']} "
                     f"fresh_coverage={s['freshly_covered']}/{s['eligible_episodes']} "
                     f"existing_alert={s['covered_without_new_activation']} "
                     f"unassessable={s['eligible_not_assessable']} control_activations={s['control_activations']}")
    controls = [(item, diagnostic) for item in report["models"]["coverage90"]["series"]
                for diagnostic in item["control_activation_diagnostics"]]
    for item, diagnostic in controls[:3]:
        row = diagnostic["evaluation"]
        predictions = ",".join(f"{h['horizon_s']:g}s:{h['predicted_value']:.4f}" for h in row["forecast_horizons"])
        lines.append(f"CONTROL {item['case_id']} {item['cid']}/{item['port_id']} "
                     f"i={row['index']} observed={row['observed_value']:.4f} predictions={predictions} "
                     f"episode_reason={diagnostic['frozen_activation']['reason']}")
    if len(controls) > 3:
        lines.append(f"additional_control_diagnostics_in_json={len(controls) - 3}")
    lines.append("status=DIAGNOSTIC_COMPLETED promotion_eligible=false")
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", required=True, type=Path)
    parser.add_argument("--campaign-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        destination = output_path(args.protocol, args.output)
        report = build_report(args.protocol, args.campaign_root)
        v1.write_new_json(destination, report)
        print("\n".join(console_lines(report)))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
