"""Train-only selection for early SLA warnings, separate from MSE development.

The three horizons share a parameter tuple in this bounded experimental family.
Selection uses recorded training episodes; calibration never enters the search.
No frozen forecasting, risk, persistence or episode code is modified.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import replace
from typing import Any, Dict, Sequence

import predictive_sla_damped_replay as replay
from qos_damped_holt import (
    DampedHorizonModel, QosDampedHoltModel, _validated_grid, forecast_records,
)
from qos_holt import _metrics, conformal_radius


CONTROLS = ("stable-low", "short-pulses")
RAMPS = ("slow-ramp", "fast-ramp")
WARNING_POLICY = dict(threshold=0.8, required_consecutive_horizons=2,
                      activation_windows=1, clear_windows=2,
                      episode_min_breach_samples=2, episode_clear_samples=2)
OBJECTIVE = {
    "version": "train-warning-lexicographic/1",
    "family": "one_shared_alpha_beta_phi_tuple_for_all_three_horizons",
    "feasibility": ["zero_control_activations", "zero_censored_activations", "at_least_one_anticipated_episode"],
    "ordered_objectives": [
        "maximize_mean_ramp_profile_mean_run_anticipated_fraction",
        "minimize_mean_ramp_profile_mean_run_late_activation_count",
        "minimize_mean_profile_mean_run_unmatched_activation_count",
        "minimize_mean_profile_mean_run_candidate_false_positive_window_rate",
        "minimize_mean_profile_mean_run_mean_horizon_forecast_mse",
    ],
    "tie_break": "largest_phi_then_smallest_alpha_then_smallest_beta",
    "weighting": "pool_correlated_ports_within_run; equal_runs_within_profile; equal_profiles",
    "lead_time": "reported_conditionally_only; not_a_selection_objective",
    "calibration_used_for_selection": False,
}


def validate_train_series(series: Sequence[Dict[str, Any]], priming: int) -> None:
    if not series or isinstance(priming, bool) or not isinstance(priming, int) or priming < 1:
        raise ValueError("treino/priming inválidos")
    identities, run_profiles = set(), defaultdict(set)
    for item in series:
        identity = item["series_id"]
        if identity in identities:
            raise ValueError("sequência de treino duplicada")
        identities.add(identity)
        run_profiles[item["run_id"]].add(item["profile"])
        if (not item["run_id"] or item["profile"] not in (*CONTROLS, *RAMPS)
                or len(item["values"]) < priming + 6
                or any(isinstance(v, bool) or not math.isfinite(v) or v < 0 for v in item["values"])):
            raise ValueError("sequência de treino inválida/curta")
    if any(len(names) != 1 for names in run_profiles.values()):
        raise ValueError("execução com perfis contraditórios")
    if {item["profile"] for item in series} != set((*CONTROLS, *RAMPS)):
        raise ValueError("treino requer os quatro perfis, incluindo os controles")


def candidate_model(parameters: Dict[str, float], *, priming: int, sample_interval_s: float) -> QosDampedHoltModel:
    """Zero-radius search placeholder: intervals cannot change candidate/activation."""
    model = QosDampedHoltModel(
        metric="utilization_ratio", sample_interval_s=sample_interval_s, coverage=.9,
        priming_samples=priming, created_at="train-warning-search",
        training={"search_placeholder": True, "intervals_calibrated": False,
                  "placeholder_calibration_samples": 1},
        # Existing artifact dataclass requires a positive sample count. This
        # internal placeholder is never written as a model or called calibrated.
        horizons=tuple(DampedHorizonModel(step, parameters["alpha"], parameters["beta"], 0.0, 1,
                                         phi=parameters["phi"]) for step in (2, 4, 6)))
    return replace(model, model_id=model.resolved_model_id())


def run_blocks(model, series: Sequence[Dict[str, Any]]) -> list:
    # Cache identity: source provenance in the final artifact can be large.
    model = replace(model, model_id=model.resolved_model_id())
    return [{**replay.replay_series(model, item, WARNING_POLICY),
             "case_id": item["run_id"], "profile": item["profile"]} for item in series]


def _profile_mean(rows: Sequence[Dict[str, Any]], field: str, profiles: Sequence[str]) -> float:
    grouped = defaultdict(list)
    for row in rows:
        if row["profile"] in profiles:
            grouped[row["profile"]].append(row[field])
    if set(grouped) != set(profiles) or any(v is None for values in grouped.values() for v in values):
        raise ValueError("objetivo sem perfis/episódios de treino suficientes")
    return sum(sum(grouped[p]) / len(grouped[p]) for p in profiles) / len(profiles)


def score_blocks(blocks: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """Whole-run/profile macro objectives; totals are descriptive, not sample size."""
    by_run = defaultdict(list)
    for block in blocks:
        by_run[block["case_id"]].append(block)
    rows = []
    for run, items in sorted(by_run.items()):
        profiles = {s["profile"] for s in items}
        if len(profiles) != 1:
            raise ValueError("execução com perfis contraditórios")
        profile = profiles.pop()
        total = replay.aggregate(items)
        if profile in RAMPS and not total["eligible_episodes"]:
            raise ValueError("rampa de treino sem episódio elegível")
        squared_by_horizon = defaultdict(list)
        for item in items:
            for row in item["rows"]:
                for prediction, actual in zip(row["predictions"], row["actual_horizons"]):
                    squared_by_horizon[prediction["horizon_steps"]].append((actual - prediction["predicted_value"]) ** 2)
        if set(squared_by_horizon) != {2, 4, 6} or not total["evaluated_windows"]:
            raise ValueError("treino sem três horizontes/janelas avaliáveis")
        rows.append(dict(
            run_id=run, profile=profile, eligible_episodes=total["eligible_episodes"],
            anticipated=total["anticipated"],
            anticipated_fraction=(total["anticipated"] / total["eligible_episodes"]
                                  if total["eligible_episodes"] else None),
            control_activations=total["control_activations"],
            late_activations=total["late_activations"], unmatched_activations=total["unmatched_activations"],
            censored_activations=total["censored_activations"],
            candidate_fp_window_rate=total["candidate"]["confusion"]["FP"] / total["evaluated_windows"],
            horizon_mean_mse=sum(sum(e) / len(e) for e in squared_by_horizon.values()) / 3))
    totals = replay.aggregate(blocks)
    feasible = (totals["control_activations"] == 0 and totals["censored_activations"] == 0
                and totals["anticipated"] > 0)
    return dict(
        feasible=feasible, anticipated_fraction=_profile_mean(rows, "anticipated_fraction", RAMPS),
        late_activation_count=_profile_mean(rows, "late_activations", RAMPS),
        unmatched_activation_count=_profile_mean(rows, "unmatched_activations", (*CONTROLS, *RAMPS)),
        candidate_fp_window_rate=_profile_mean(rows, "candidate_fp_window_rate", (*CONTROLS, *RAMPS)),
        forecast_mse=_profile_mean(rows, "horizon_mean_mse", (*CONTROLS, *RAMPS)),
        totals={k: totals[k] for k in ("workload_runs", "correlated_port_sequences", "eligible_episodes",
                                      "anticipated", "late_activations", "control_activations",
                                      "unmatched_activations", "censored_activations", "lead_time_s")},
        per_run=rows)


def selection_key(candidate: Dict[str, Any]) -> tuple:
    score, p = candidate["score"], candidate["parameters"]
    return (-score["anticipated_fraction"], score["late_activation_count"], score["unmatched_activation_count"],
            score["candidate_fp_window_rate"], score["forecast_mse"], -p["phi"], p["alpha"], p["beta"])


def choose_parameters(*, train_series: Sequence[Dict[str, Any]], priming: int, sample_interval_s: float,
                      alphas: Sequence[float], betas: Sequence[float], phis: Sequence[float]) -> Dict[str, Any]:
    """No calibration or v2 argument exists here. Search only training sequences."""
    validate_train_series(train_series, priming)
    grids = [_validated_grid(values, name, zero) for values, name, zero in (
        (alphas, "alpha", False), (betas, "beta", True), (phis, "phi", False))]
    candidates = []
    for alpha in grids[0]:
        for beta in grids[1]:
            for phi in grids[2]:
                parameters = dict(alpha=alpha, beta=beta, phi=phi)
                blocks = run_blocks(candidate_model(parameters, priming=priming, sample_interval_s=sample_interval_s), train_series)
                candidates.append(dict(parameters=parameters, score=score_blocks(blocks)))
    feasible = sorted((c for c in candidates if c["score"]["feasible"]), key=selection_key)
    return dict(objective=OBJECTIVE, candidate_count=len(candidates), feasible_candidates=len(feasible),
                selected=feasible[0] if feasible else None, candidates=candidates,
                intervals_during_search="zero_radius_placeholder_not_a_calibrated_artifact",
                watch_used_for_selection=False, calibration_used_for_selection=False, v2_used_for_selection=False)


def calibrate_selected(*, parameters: Dict[str, float], train_series: Sequence[Dict[str, Any]],
                       calibration_series: Sequence[Dict[str, Any]], priming: int, sample_interval_s: float,
                       created_at: str, metadata: Dict[str, Any]) -> QosDampedHoltModel:
    """Freeze tuple first, then use calibration residuals solely for interval radii."""
    if (not calibration_series or {s["run_id"] for s in train_series} & {s["run_id"] for s in calibration_series}
            or {s["series_id"] for s in train_series} & {s["series_id"] for s in calibration_series}):
        raise ValueError("treino/calibração vazios ou sobrepostos")
    horizons = []
    for step in (2, 4, 6):
        train = [r for s in train_series for r in forecast_records(
            s["values"], **parameters, horizon_steps=step, priming_samples=priming)]
        calibration = [r for s in calibration_series for r in forecast_records(
            s["values"], **parameters, horizon_steps=step, priming_samples=priming)]
        if not calibration:
            raise ValueError("calibração sem previsões suficientes")
        radius = conformal_radius([r[2] for r in calibration], .9)
        horizons.append(DampedHorizonModel(
            step, parameters["alpha"], parameters["beta"], radius, len(calibration), phi=parameters["phi"],
            training_metrics=_metrics(train), calibration_metrics=_metrics(calibration, radius)))
    model = QosDampedHoltModel(
        metric="utilization_ratio", sample_interval_s=sample_interval_s, coverage=.9, priming_samples=priming,
        created_at=created_at, horizons=tuple(horizons),
        training={**metadata, "selection_objective": OBJECTIVE, "warning_policy": WARNING_POLICY,
                  "validation_scope": "posthoc_warning_objective_development_no_holdout",
                  "promotion_eligible": False, "deployment_eligible": False, "test_evaluated": False})
    return QosDampedHoltModel.from_dict(model.to_dict())


def warning_signature(blocks: Sequence[Dict[str, Any]]) -> dict:
    """Prove that adding calibrated intervals does not alter selected warnings."""
    return {s["series_id"]: dict(
        episode_events=s["episode_events"],
        rows=[dict(index=r["index"], points=[p["predicted_value"] for p in r["predictions"]],
                   candidate=r["candidate"], active=r["active"], activation=r["activation"],
                   clear_transition=r["clear_transition"]) for r in s["rows"]]) for s in blocks}
