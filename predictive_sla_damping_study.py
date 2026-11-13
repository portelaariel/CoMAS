#!/usr/bin/env python3
"""Offline, post-hoc damping sensitivity; never replace the frozen v2 results.

Only point forecasts are studied. Original conformal intervals are NOT reused
for changed forecasts; WATCH and interval coverage are deliberately not scored.
No fitting, model selection, runtime configuration or actuation is performed.
"""

from __future__ import annotations

import argparse
import json
import math
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Sequence

import predictive_sla_diagnostics as diagnostics
import predictive_sla_validation as v1
import predictive_sla_validation_v2 as v2
from backtest_sla_risk import _actual_future_outcome, _classification_block, _update_confusion, backtest_model
from qos_holt import QosHoltModel, _finite, _updated_state
from sla_episode_evaluation import evaluate_episodes, summarize_episode_reports, validate_timestamps
from sla_risk import SLA_RISK_EVENT_TYPE, SlaRiskPersistence, SlaRiskPolicy, _first_consecutive_run


ROOT = Path(__file__).resolve().parent
SCHEMA = "comas-predictive-sla-damping-sensitivity/1"
PHI_GRID = (1.0, 0.98, 0.95, 0.90, 0.80)
METHOD_REFERENCE = "https://www.statsmodels.org/stable/_modules/statsmodels/tsa/holtwinters/model.html"
STUDY_POLICY = {
    "method": "additive_damped_holt_state_and_projection",
    "phi_grid": list(PHI_GRID),
    "grid_basis": "engineering_sensitivity_grid_chosen_after_v2_not_validated_parameters",
    "alpha_beta": "fixed_per_horizon_from_frozen_coverage90_model; no_refit",
    "initialization": "first_observation_as_level; zero_trend; reset_each_series",
    "nonnegative_forecast": "same_max_zero_and_12_decimal_rounding_as_frozen_Holt",
    "intervals": "NOT_EVALUATED; modified_forecasts_require_separate_recalibration",
    "selection": "NONE; report_all_variants_without_ranking_or_promotion",
    "method_reference": METHOD_REFERENCE,
}
LIMITATIONS = [
    "The damping family and grid were chosen after inspecting v2 failures; these are development data, not holdout validation.",
    "All phi values are reported; none is fitted, selected or deployed by this study.",
    "Alpha and beta were trained for undamped Holt and are not necessarily optimal for damped variants.",
    "The original calibrated intervals are not valid for changed forecasts and are not reused; WATCH is not evaluated.",
    "Frozen v2 results, thresholds, activation/clearing rules and observed episode definitions remain unchanged.",
    "Conditional warning lead times concern detected episodes only; missed episodes and control activations remain explicit.",
    "Both ports and successive windows are correlated; episode counts are not independent workload runs.",
    "New training/calibration and a separately frozen prospective campaign are required before any promotion claim.",
    "No preventive action, SLA protection, LLM decision or scalability is evaluated.",
]


class DampedHoltForecaster:
    """Past-only additive damped Holt; phi=1 exactly reproduces native states."""

    def __init__(self, model: QosHoltModel, phi: float):
        if isinstance(phi, bool):
            raise ValueError("phi deve estar em (0, 1]")
        self.phi = _finite(phi, "phi")
        if not 0 < self.phi <= 1:
            raise ValueError("phi deve estar em (0, 1]")
        self.model = model
        self.states = {h.horizon_steps: dict(level=None, trend=0.0, count=0)
                       for h in model.horizons}

    def update(self, observed_value: float) -> List[Dict[str, float]]:
        observed = _finite(observed_value, "observation")
        if observed < 0:
            raise ValueError("observação negativa")
        forecasts = []
        for h in self.model.horizons:
            state = self.states[h.horizon_steps]
            previous = state["level"]
            if self.phi == 1:
                level, trend = _updated_state(previous, state["trend"], observed, h.alpha, h.beta)
            elif previous is None:
                level, trend = observed, 0.0
            else:
                damped_trend = self.phi * state["trend"]
                level = h.alpha * observed + (1 - h.alpha) * (previous + damped_trend)
                trend = h.beta * (level - previous) + (1 - h.beta) * damped_trend
            if not math.isfinite(level) or not math.isfinite(trend):
                raise ValueError("estado Holt não finito")
            state.update(level=level, trend=trend, count=state["count"] + 1)
            if state["count"] < self.model.priming_samples:
                continue
            multiplier = (h.horizon_steps if self.phi == 1 else
                          sum(self.phi ** step for step in range(1, h.horizon_steps + 1)))
            predicted = level + multiplier * trend
            if not math.isfinite(predicted):
                raise ValueError("previsão Holt não finita")
            forecasts.append(dict(horizon_steps=h.horizon_steps,
                                  horizon_s=h.horizon_steps * self.model.sample_interval_s,
                                  predicted_value=round(max(0.0, predicted), 12),
                                  level=level, trend=trend))
        return forecasts


def error_metrics(residuals: Sequence[float]) -> Dict[str, Any]:
    """Residual is observed minus predicted; no fabricated zero for no scores."""
    if not residuals:
        return dict(samples=0, mae=None, rmse=None, bias=None)
    return dict(samples=len(residuals), mae=sum(abs(r) for r in residuals) / len(residuals),
                rmse=math.sqrt(sum(r * r for r in residuals) / len(residuals)),
                bias=sum(residuals) / len(residuals))


def replay_series(model: QosHoltModel, series: Dict[str, Any], policy: Dict[str, Any],
                  phi: float) -> tuple:
    """Keep native scoring scope and episode matcher; never feed future values."""
    values, timestamps = series["values"], series["timestamps_ns"]
    validate_timestamps(timestamps, len(values))
    risk = SlaRiskPolicy(metric=model.metric, comparator="MAX", threshold=policy["threshold"],
                         horizons_steps=tuple(h.horizon_steps for h in model.horizons),
                         required_consecutive_horizons=policy["required_consecutive_horizons"])
    maximum_horizon = max(risk.horizons_steps)
    forecaster = DampedHoltForecaster(model, phi)
    persistence = SlaRiskPersistence(activation_windows=policy["activation_windows"],
                                    clear_windows=policy["clear_windows"])
    rows, observations, points, candidates = [], [], {}, {}
    confusion, active_confusion = Counter(), Counter()
    residuals = {h.horizon_steps: [] for h in model.horizons}
    for index, observed in enumerate(values):
        forecasts = forecaster.update(observed)
        if not forecasts or index + maximum_horizon >= len(values):
            continue
        candidate = _first_consecutive_run(
            [f["predicted_value"] >= risk.threshold for f in forecasts],
            risk.required_consecutive_horizons) is not None
        # WATCH and NORMAL both interrupt activation and clear native persistence.
        # No invented intervals are passed to the calibrated forecast contract.
        state = persistence.update(dict(cid=series["cid"], metric=model.metric,
                                        subject=dict(id=series["port_id"]),
                                        decision=SLA_RISK_EVENT_TYPE if candidate else "NORMAL"))
        actual = _actual_future_outcome(values, index, risk)
        _update_confusion(confusion, candidate, actual["positive"])
        _update_confusion(active_confusion, state["active"], actual["positive"])
        activation = bool(state["active"] and state["transitioned"])
        rows.append(dict(index=index, ts_ns=timestamps[index], observed_value=observed,
                         candidate=candidate, active=state["active"], activation=activation,
                         clear_transition=bool(state["transitioned"] and not state["active"]),
                         predictions=forecasts,
                         actual_horizons=[dict(horizon_steps=f["horizon_steps"],
                                               actual_value=values[index + f["horizon_steps"]])
                                          for f in forecasts]))
        observations.append(dict(index=index, persistent_activation=activation))
        key = series["series_id"], index
        points[key] = tuple(f["predicted_value"] for f in forecasts)
        candidates[key] = candidate
        for f in forecasts:
            residuals[f["horizon_steps"]].append(values[index + f["horizon_steps"]] - f["predicted_value"])
    episodes = evaluate_episodes(
        values=values, observations=observations, timestamps_ns=timestamps,
        series_id=series["series_id"], cid=series["cid"], port_id=series["port_id"],
        comparator="MAX", threshold=risk.threshold, sample_interval_s=model.sample_interval_s,
        max_horizon_steps=maximum_horizon, min_breach_samples=policy["episode_min_breach_samples"],
        clear_samples=policy["episode_clear_samples"])
    block = dict(series_id=series["series_id"], cid=series["cid"], port_id=series["port_id"],
                 evaluated_windows=len(rows), candidate=_classification_block(confusion),
                 persistent_active=_classification_block(active_confusion), episode_events=episodes,
                 clear_transitions=sum(row["clear_transition"] for row in rows),
                 forecast_errors={str(step): error_metrics(errors) for step, errors in residuals.items()})
    if phi == 1:
        native, native_points, native_candidates = backtest_model(model=model, series=[series], **policy)
        reference = native["series"][0]
        if (points != native_points or candidates != native_candidates
                or episodes != reference["episode_events"]
                or block["candidate"] != reference["candidate"]
                or block["persistent_active"] != {key: reference["persistent_active"][key]
                                                  for key in ("confusion", "metrics")}
                or block["clear_transitions"] != reference["persistent_active"]["clear_transitions"]):
            raise ValueError("baseline phi=1 diverge dos sinais congelados")
        block["native_reference_matches"] = True
    return block, rows, residuals


def pooled_errors(items: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Pool horizon errors with sample weights, not an unweighted mean of runs."""
    result = {}
    for step in sorted({step for item in items for step in item["forecast_errors"]}, key=int):
        scores = [item["forecast_errors"][step] for item in items if step in item["forecast_errors"]]
        count = sum(score["samples"] for score in scores)
        if not count:
            result[step] = error_metrics([])
            continue
        scored = [score for score in scores if score["samples"]]
        result[step] = dict(samples=count,
                            mae=sum(s["samples"] * s["mae"] for s in scored) / count,
                            rmse=math.sqrt(sum(s["samples"] * s["rmse"] ** 2 for s in scored) / count),
                            bias=sum(s["samples"] * s["bias"] for s in scored) / count)
    return result


def aggregate(items: Sequence[Dict[str, Any]], residuals: Dict[int, List[float]] | None = None) -> Dict[str, Any]:
    confusion = Counter()
    for item in items:
        confusion.update(item["candidate"]["confusion"])
    episodes = summarize_episode_reports([item["episode_events"] for item in items])
    return dict(workload_runs=len({item["case_id"] for item in items}), series=len(items),
                evaluated_windows=sum(item["evaluated_windows"] for item in items),
                candidate=_classification_block(confusion),
                eligible_episodes=episodes["eligible_episodes"], anticipated=episodes["detected"],
                missed=episodes["missed"], total_activations=episodes["total_activations"],
                unmatched_activations=episodes["unmatched_activations"],
                censored_activations=episodes["censored_activations"],
                lead_time_s=episodes["warning_lead_time_s"],
                control_activations=sum(item["episode_events"]["total_activations"] for item in items
                                        if item["profile"] in ("stable-low", "short-pulses")),
                forecast_errors=(pooled_errors(items) if residuals is None else
                                 {str(step): error_metrics(errors) for step, errors in residuals.items()}))


def paired_changes(baseline: Dict[str, Any], variant: Dict[str, Any]) -> Dict[str, Any]:
    before = {e["episode_id"]: e for item in baseline["series"] for e in item["episode_events"]["episodes"]}
    after = {e["episode_id"]: e for item in variant["series"] for e in item["episode_events"]["episodes"]}
    if (set(before) != set(after)
            or any((before[key]["onset_index"], before[key]["eligible"])
                   != (after[key]["onset_index"], after[key]["eligible"]) for key in before)):
        raise ValueError("amortecimento não pode alterar o ground truth ou sua elegibilidade")
    return dict(
        anticipated_delta=variant["summary"]["anticipated"] - baseline["summary"]["anticipated"],
        control_activation_delta=variant["summary"]["control_activations"] - baseline["summary"]["control_activations"],
        candidate_fp_delta=variant["summary"]["candidate"]["confusion"]["FP"] - baseline["summary"]["candidate"]["confusion"]["FP"],
        lost_anticipated_episodes=[key for key in before if before[key]["eligible"]
                                  and before[key]["detected"] and not after[key]["detected"]],
        gained_anticipated_episodes=[key for key in before if before[key]["eligible"]
                                    and not before[key]["detected"] and after[key]["detected"]])


def build_report(protocol_path: Path, campaign: Path) -> Dict[str, Any]:
    protocol_path, campaign = protocol_path.resolve(), campaign.resolve()
    analysis_paths = (Path(__file__).resolve(), Path(diagnostics.__file__).resolve())
    code = {str(p): v1.digest_file(p) for p in analysis_paths}
    protocol = v2.load_protocol(protocol_path)
    before = diagnostics._sources_snapshot(protocol, protocol_path, campaign)
    verified = v2.evaluate_campaign(protocol_path, campaign)
    if verified["status"] != "COMPLETED":
        raise ValueError("estudo requer 12 execuções v2 válidas e encerradas")
    summary_path = campaign / "campaign-summary.json"
    if json.loads(summary_path.read_text(encoding="utf-8")) != verified:
        raise ValueError("relatório v2 diverge da reavaliação congelada")
    model = QosHoltModel.load(protocol_path.parent / protocol["models"]["coverage90"]["path"])
    variants = {f"phi{phi:g}": dict(phi=phi, series=[]) for phi in PHI_GRID}
    errors = {name: {h.horizon_steps: [] for h in model.horizons} for name in variants}
    for case, expected in zip(protocol["cases"], verified["cases"]):
        subjects, record, hashes = v1._read_case(protocol, case, campaign / case["case_id"])
        if hashes != expected["source_sha256"]:
            raise ValueError("fontes v2 mudaram após a reavaliação congelada")
        for series, source in zip(subjects, record["sources"]):
            baseline_rows = None
            for name, variant in variants.items():
                block, rows, residuals = replay_series(model, series, protocol["policy"], variant["phi"])
                if variant["phi"] == 1:
                    baseline_rows = rows
                reference_controls = [row["index"] for row in baseline_rows if row["activation"]]
                if case["profile"] not in ("stable-low", "short-pulses"):
                    reference_controls = []
                block.update(case_id=case["case_id"], profile=case["profile"], repetition=case["repetition"],
                             source_sha256=source["sha256"],
                             baseline_control_context=[row for row in rows
                                                       if any(abs(row["index"] - i) <= 2 for i in reference_controls)])
                variant["series"].append(block)
                for step, values in residuals.items():
                    errors[name][step].extend(values)
    for name, variant in variants.items():
        variant["summary"] = aggregate(variant["series"], errors[name])
        variant["per_profile"] = {profile: aggregate([s for s in variant["series"] if s["profile"] == profile])
                                  for profile in v1.profiles()}
        variant["per_run"] = {case["case_id"]: aggregate([s for s in variant["series"]
                                                          if s["case_id"] == case["case_id"]])
                              for case in protocol["cases"]}
    baseline = variants["phi1"]["summary"]
    frozen = verified["models"]["coverage90"]
    if (baseline["candidate"] != frozen["pooled_window_candidate"]
            or baseline["anticipated"] != frozen["episode_events"]["detected"]
            or baseline["eligible_episodes"] != frozen["episode_events"]["eligible_episodes"]):
        raise ValueError("baseline agregado diverge da avaliação oficial")
    for variant in variants.values():
        variant["versus_baseline"] = paired_changes(variants["phi1"], variant)
    v2.load_protocol(protocol_path)
    if (diagnostics._sources_snapshot(protocol, protocol_path, campaign) != before
            or {str(p): v1.digest_file(p) for p in analysis_paths} != code):
        raise ValueError("fontes ou código mudaram durante o estudo")
    return v1.seal(dict(
        schema_version=SCHEMA, created_ns=time.time_ns(), status="SENSITIVITY_COMPLETED",
        scope="posthoc_development_sensitivity_not_confirmatory_validation",
        promotion_eligible=False, deployment_eligible=False, selected_variant=None,
        study_policy=dict(STUDY_POLICY), original_risk_policy=protocol["policy"],
        base_model_id=model.resolved_model_id(),
        fixed_horizons=[dict(horizon_steps=h.horizon_steps, horizon_s=h.horizon_steps * model.sample_interval_s,
                             alpha=h.alpha, beta=h.beta) for h in model.horizons],
        git_commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        analysis_code_sha256=code, frozen_protocol_code_sha256=protocol["code_sha256"], source_sha256=before,
        official_v2=dict(protocol_sha256=protocol["protocol_sha256"],
                         summary_sha256=before[str(summary_path)], status=verified["status"],
                         criteria_status=verified["criteria_status"], checks=verified["checks"],
                         models=verified["models"]),
        baseline_reference_matches=True, variants=variants, limitations=list(LIMITATIONS)), "report_sha256")


def output_path(protocol_path: Path, output: Path) -> Path:
    output = output.resolve()
    if (output.exists() or output.parent != protocol_path.resolve().parent
            or output.suffix != ".json" or not output.name.startswith("damping-sensitivity")):
        raise ValueError("use um novo damping-sensitivity*.json dentro do diretório v2")
    return output


def console_lines(report: Dict[str, Any]) -> List[str]:
    official = report["official_v2"]
    lines = [f"official_v2={official['status']} criteria={official['criteria_status']} unchanged=true baseline_exact=true"]
    for variant in report["variants"].values():
        s = variant["summary"]
        lead = s["lead_time_s"]["mean"]
        lead_text = "N/A" if lead is None else f"{lead:.3f}s"
        lines.append(f"phi={variant['phi']:g}: anticipated={s['anticipated']}/{s['eligible_episodes']} "
                     f"control={s['control_activations']} unmatched={s['unmatched_activations']} "
                     f"FP={s['candidate']['confusion']['FP']} lead={lead_text} "
                     f"lost={len(variant['versus_baseline']['lost_anticipated_episodes'])}")
    lines.append("status=SENSITIVITY_COMPLETED selected_variant=NONE promotion_eligible=false")
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
